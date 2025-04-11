// server.js - Servidor completo para la aplicación Sweet Delights con MongoDB
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const WebSocket = require('ws');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 5000;

// Crear servidor HTTP a partir de Express
const server = http.createServer(app);

// Configuración de MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://2022371082:marianahernandezdimas15102004@cluster0.k11jy.mongodb.net/sweet-delights?retryWrites=true&w=majority&appName=Cluster0';

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL || 'maridimas08@gmail.com',
    pass: process.env.EMAIL_PASS || 'sbfj zrnm xogs lynq'
  }
});

// Configuración de Twilio (simplificada)
let twilioClient = null;
let twilioPhoneNumber = null;

// Esquemas de MongoDB
const userSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  apellido: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  domicilio: { type: String, required: true },
  phone: { type: String }, // Para recuperación por SMS
  role: { type: String, enum: ['user', 'admin', 'superAdmin'], default: 'user' },
  mfaEnabled: { type: Boolean, default: false },
  mfaSecret: { type: String },
  securityQuestion: { type: String },
  securityAnswer: { type: String },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  verificationCode: String,
  verificationCodeExpires: Date,
  tempToken: String,
  tempTokenExpires: Date,
  createdAt: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, required: true },
  category: { type: String, required: true },
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const favoriteSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  productIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }]
});

// Modelos
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Favorite = mongoose.model('Favorite', favoriteSchema);

// Middleware
app.use(cors()); 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || '84f5d94b3bf51171253c9d4f7d1d506ce3c1b6a5a8c761660d489c6ab03ad65a';

// Middleware de autenticación
const verifyToken = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Token no proporcionado' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

// Middleware de rol de administrador
const isAdmin = (req, res, next) => {
  if (req.userRole !== 'admin' && req.userRole !== 'superAdmin') {
    return res.status(403).json({ message: 'Acceso denegado' });
  }
  
  next();
};

// Helpers
const comparePassword = async (candidatePassword, hashedPassword) => {
  return bcrypt.compare(candidatePassword, hashedPassword);
};

// Rutas de autenticación
app.post('/api/auth/register', async (req, res) => {
  try {
    const { nombre, apellido, email, password, domicilio, phone, securityQuestion, securityAnswer } = req.body;
    
    // Verificar si el email ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'El email ya está registrado' });
    }
    
    // Verificar si el teléfono ya existe (si se proporciona)
    if (phone) {
      const existingPhone = await User.findOne({ phone });
      if (existingPhone) {
        return res.status(400).json({ message: 'El número de teléfono ya está registrado' });
      }
    }
    
    // Hashear contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Crear nuevo usuario
    const newUser = new User({
      nombre,
      apellido,
      email,
      password: hashedPassword,
      domicilio,
      phone, // Opcional
      securityQuestion, // Opcional
      securityAnswer, // Opcional
      role: 'user'
    });
    
    await newUser.save();
    
    // Generar token
    const token = jwt.sign(
      { userId: newUser._id, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      token,
      user: {
        _id: newUser._id,
        nombre: newUser.nombre,
        apellido: newUser.apellido,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, mfaToken, tempToken } = req.body;
    
    // Caso 1: Login con MFA después de verificación inicial
    if (tempToken && mfaToken) {
      // Buscar usuario por token temporal
      const user = await User.findOne({
        tempToken,
        tempTokenExpires: { $gt: Date.now() }
      });
      
      if (!user) {
        return res.status(401).json({ message: 'Token temporal inválido o expirado' });
      }
      
      // Verificar código MFA
      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: mfaToken,
        window: 1
      });
      
      if (!verified) {
        return res.status(401).json({ message: 'Código MFA inválido' });
      }
      
      // Limpiar token temporal
      user.tempToken = undefined;
      user.tempTokenExpires = undefined;
      await user.save();
      
      // Generar token JWT
      const token = jwt.sign(
        { userId: user._id, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      res.json({
        token,
        user: {
          _id: user._id,
          nombre: user.nombre,
          apellido: user.apellido,
          email: user.email,
          role: user.role,
          mfaEnabled: user.mfaEnabled
        }
      });
      
      return;
    }
    
    // Caso 2: Login normal
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    // Verificar contraseña
    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    // Si MFA está habilitado, generar token temporal
    if (user.mfaEnabled) {
      // Generar token temporal
      const tempToken = crypto.randomBytes(20).toString('hex');
      
      user.tempToken = tempToken;
      user.tempTokenExpires = Date.now() + 600000; // 10 minutos
      await user.save();
      
      return res.status(200).json({ 
        mfaRequired: true,
        tempToken
      });
    }
    
    // Si MFA no está habilitado, generar token JWT normalmente
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        _id: user._id,
        nombre: user.nombre,
        apellido: user.apellido,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email requerido para recuperar contraseña' });
    }
    
    const user = await User.findOne({ email });
    
    // Si no se encuentra el usuario, devolver mensaje genérico por seguridad
    if (!user) {
      return res.json({ 
        success: true,
        message: 'Si existe una cuenta con este email, se ha enviado un código de recuperación.' 
      });
    }
    
    // Generar token de restablecimiento más seguro usando verificación de código
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Guardar código y tiempo de expiración (15 minutos)
    user.verificationCode = verificationCode;
    user.verificationCodeExpires = Date.now() + 900000;
    
    // Generar un token de restablecimiento separado
    const resetPasswordToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordExpires = Date.now() + 900000; // 15 minutos
    
    await user.save();
    
    // Enviar por correo electrónico
    const mailOptions = {
      from: process.env.EMAIL || 'maridimas08@gmail.com',
      to: user.email,
      subject: 'SweetCake - Código de recuperación de contraseña',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #ff6b6b;">SweetCake - Recuperación de Contraseña</h2>
          <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
          <p>Tu código de verificación es:</p>
          <div style="background-color: #f7f7f7; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
            ${verificationCode}
          </div>
          <p>Token de restablecimiento: ${resetPasswordToken}</p>
          <p>Este código expirará en 15 minutos.</p>
          <p>Si no solicitaste un cambio de contraseña, ignora este mensaje.</p>
          <p>Saludos,<br>El equipo de SweetCake</p>
        </div>
      `
    };
    
    // Mostrar el código en la consola para desarrollo
    console.log(`Código de verificación enviado por email: ${verificationCode}`);
    console.log(`Token de restablecimiento: ${resetPasswordToken}`);
    
    // Enviar el email
    await transporter.sendMail(mailOptions);
    
    res.json({ 
      success: true,
      message: 'Se ha enviado un código de verificación a su correo electrónico.',
      resetPasswordToken 
    });
  } catch (error) {
    console.error('Error en forgot-password:', error);
    res.status(500).json({ 
      message: 'Error en el servidor', 
      details: error.message 
    });
  }
});

app.post('/api/auth/verify-recovery-code', async (req, res) => {
  try {
    const { email, verificationCode, newPassword } = req.body;
    
    if (!verificationCode) {
      return res.status(400).json({ message: 'Código de verificación requerido' });
    }
    
    if (!email) {
      return res.status(400).json({ message: 'Email requerido' });
    }
    
    // Buscar usuario por email
    const user = await User.findOne({ 
      email,
      verificationCode,
      verificationCodeExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Código inválido o expirado' });
    }
    
    // Si se proporciona una nueva contraseña, actualizarla
    if (newPassword) {
      // Hashear nueva contraseña
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
    }
    
    // Limpiar código de verificación
    user.verificationCode = undefined;
    user.verificationCodeExpires = undefined;
    
    await user.save();
    
    // Si no se proporcionó contraseña, simplemente validamos el código
    if (!newPassword) {
      return res.json({ 
        success: true,
        message: 'Código verificado correctamente',
        verified: true
      });
    }
    
    // Si llegamos aquí, es porque se cambió la contraseña
    res.json({ 
      success: true,
      message: 'Contraseña actualizada exitosamente' 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password, verificationCode } = req.body;
    
    console.log('Token recibido:', token);
    console.log('Password recibida:', password);
    console.log('Verification Code:', verificationCode);
    
    // Buscar usuario con token válido o código de verificación válido
    const user = await User.findOne({
      $or: [
        { 
          resetPasswordToken: token,
          resetPasswordExpires: { $gt: Date.now() } 
        },
        { 
          verificationCode: verificationCode || token,
          verificationCodeExpires: { $gt: Date.now() } 
        }
      ]
    });
    
    // Si no se encuentra el usuario, el token no es válido
    if (!user) {
      return res.status(400).json({ 
        message: 'El token es inválido o ha expirado',
        tokenValid: false
      });
    }
    
    // Si se proporciona contraseña, proceder con el restablecimiento
    if (password) {
      // Validar requisitos de contraseña
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(password)) {
        return res.status(400).json({ 
          message: 'La contraseña no cumple con los requisitos de seguridad. Debe tener al menos 8 caracteres, incluir mayúsculas, minúsculas, números y caracteres especiales.' 
        });
      }
      
      // Hashear nueva contraseña
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      
      // Limpiar tokens y códigos
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      user.verificationCode = undefined;
      user.verificationCodeExpires = undefined;
      
      await user.save();
      
      // Enviar email de notificación
      try {
        await transporter.sendMail({
          from: process.env.EMAIL || 'maridimas08@gmail.com',
          to: user.email,
          subject: 'Contraseña Restablecida - SweetCake',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #ff6b6b;">SweetCake - Contraseña Restablecida</h2>
              <p>Su contraseña ha sido restablecida exitosamente.</p>
              <p>Si no realizó este cambio, por favor contacte a nuestro soporte inmediatamente.</p>
              <p>Fecha: ${new Date().toLocaleString()}</p>
              <p>Saludos,<br>El equipo de SweetCake</p>
            </div>
          `
        });
      } catch (emailError) {
        console.error('Error enviando email de notificación:', emailError);
      }
      
      return res.json({ 
        message: 'Contraseña actualizada exitosamente',
        success: true
      });
    }
    
    // Si no hay contraseña, solo validar el token
    return res.json({ 
      message: 'Token válido',
      tokenValid: true 
    });
  } catch (error) {
    console.error('Error en reset-password:', error);
    res.status(500).json({ 
      message: 'Error en el servidor', 
      details: error.message 
    });
  }
});

// Modificar la ruta de olvidar contraseña para generar tokens más seguros
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email requerido para recuperar contraseña' });
    }
    
    const user = await User.findOne({ email });
    
    // Si no se encuentra el usuario, devolver mensaje genérico por seguridad
    if (!user) {
      return res.json({ 
        success: true,
        message: 'Si existe una cuenta con este email, se ha enviado un enlace de recuperación.' 
      });
    }
    
    // Generar token de restablecimiento más seguro
    const resetPasswordToken = crypto.randomBytes(32).toString('hex');
    
    // Establecer token y tiempo de expiración (15 minutos)
    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordExpires = Date.now() + 900000; // 15 minutos
    await user.save();
    
    // Enviar correo de recuperación
    const mailOptions = {
      from: process.env.EMAIL || 'maridimas08@gmail.com',
      to: user.email,
      subject: 'SweetCake - Restablecimiento de Contraseña',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #ff6b6b;">SweetCake - Restablecimiento de Contraseña</h2>
          <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
          <p>Haz clic en el siguiente enlace para cambiar tu contraseña:</p>
          <a href="http://localhost:3000/reset-password/${resetPasswordToken}" 
             style="background-color: #ff6b6b; color: white; padding: 10px 20px; 
                    text-decoration: none; border-radius: 5px;">
            Restablecer Contraseña
          </a>
          <p>Este enlace expirará en 15 minutos.</p>
          <p>Si no solicitaste un cambio de contraseña, ignora este mensaje.</p>
          <p>Saludos,<br>El equipo de SweetCake</p>
        </div>
      `
    };
    
    // Enviar el email
    await transporter.sendMail(mailOptions);
    
    res.json({ 
      success: true,
      message: 'Se ha enviado un enlace de recuperación a su correo electrónico.' 
    });
  } catch (error) {
    console.error('Error en forgot-password:', error);
    res.status(500).json({ 
      message: 'Error en el servidor', 
      details: error.message 
    });
  }
});

// Rutas de MFA
app.post('/api/auth/setup-mfa', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Generar secreto para TOTP (Time-based One Time Password)
    const secret = speakeasy.generateSecret({
      name: `SweetCake:${user.email}`
    });
    
    // Guardar el secreto temporalmente
    user.mfaSecret = secret.base32;
    await user.save();
    
    // Generar URL para código QR
    const otpauthUrl = secret.otpauth_url;
    const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);
    
    res.json({
      secret: secret.base32,
      qrCodeUrl
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/auth/verify-mfa', verifyToken, async (req, res) => {
  try {
    const { verificationCode } = req.body;
    
    if (!verificationCode) {
      return res.status(400).json({ message: 'Se requiere código de verificación' });
    }
    
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (!user.mfaSecret) {
      return res.status(400).json({ message: 'Primero debe configurar MFA' });
    }
    
    // Verificar el código proporcionado
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: verificationCode,
      window: 1  // Permite un margen de 1 intervalo (±30 segundos)
    });
    
    if (!verified) {
      return res.status(400).json({ message: 'Código de verificación inválido' });
    }
    
    // Activar MFA para el usuario
    user.mfaEnabled = true;
    await user.save();
    
    res.json({ message: 'MFA activado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/auth/disable-mfa', verifyToken, async (req, res) => {
  try {
    const { verificationCode } = req.body;
    
    if (!verificationCode) {
      return res.status(400).json({ message: 'Se requiere código de verificación' });
    }
    
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (!user.mfaEnabled) {
      return res.status(400).json({ message: 'MFA no está activado' });
    }
    
    // Verificar el código proporcionado
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: verificationCode,
      window: 1
    });
    
    if (!verified) {
      return res.status(400).json({ message: 'Código de verificación inválido' });
    }
    
    // Desactivar MFA
    user.mfaEnabled = false;
    user.mfaSecret = undefined;
    await user.save();
    
    res.json({ message: 'MFA desactivado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Rutas de usuarios
app.get('/api/users', verifyToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/api/users/:id', verifyToken, async (req, res) => {
  try {
    // Verificar si el usuario solicita su propia info o es admin
    if (req.params.id !== req.userId && req.userRole !== 'admin') {
      return res.status(403).json({ message: 'Acceso denegado' });
    }
    
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.put('/api/users/:id', verifyToken, async (req, res) => {
  try {
    // Verificar permisos
    if (req.params.id !== req.userId && req.userRole !== 'admin') {
      return res.status(403).json({ message: 'Acceso denegado' });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const { nombre, apellido, domicilio, role, phone, securityQuestion, securityAnswer } = req.body;
    
    if (nombre) user.nombre = nombre;
    if (apellido) user.apellido = apellido;
    if (domicilio) user.domicilio = domicilio;
    if (phone) user.phone = phone;
    if (securityQuestion) user.securityQuestion = securityQuestion;
    if (securityAnswer) user.securityAnswer = securityAnswer;
    
    // Solo admins pueden cambiar roles
    if (role && req.userRole === 'admin') {
      user.role = role;
    }
    
    await user.save();
    
    res.json({
      _id: user._id,
      nombre: user.nombre,
      apellido: user.apellido,
      email: user.email,
      domicilio: user.domicilio,
      phone: user.phone,
      role: user.role,
      mfaEnabled: user.mfaEnabled
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.delete('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    // Prevenir eliminación del propio usuario
    if (req.params.id === req.userId) {
      return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta' });
    }
    
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Eliminar favoritos del usuario
    await Favorite.deleteOne({ userId: req.params.id });
    
    res.json({ message: 'Usuario eliminado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Rutas de productos
app.get('/api/products', async (req, res) => {
  try {
    const { search, category } = req.query;
    let query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (category) {
      query.category = { $regex: new RegExp(`^${category}$`, 'i') };
    }
    
    const products = await Product.find(query);
    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }
    
    res.json(product);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/products', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, description, price, image, category, isAvailable } = req.body;
    
    const newProduct = new Product({
      name,
      description,
      price: Number(price),
      image,
      category,
      isAvailable: Boolean(isAvailable)
    });
    
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.put('/api/products/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, description, price, image, category, isAvailable } = req.body;
    
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }
    
    if (name) product.name = name;
    if (description) product.description = description;
    if (price) product.price = Number(price);
    if (image) product.image = image;
    if (category) product.category = category;
    if (isAvailable !== undefined) product.isAvailable = Boolean(isAvailable);
    
    await product.save();
    res.json(product);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.delete('/api/products/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }
    
    // Eliminar de favoritos
    await Favorite.updateMany(
      { productIds: req.params.id },
      { $pull: { productIds: req.params.id } }
    );
    
    res.json({ message: 'Producto eliminado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Rutas de favoritos
app.get('/api/favorites', verifyToken, async (req, res) => {
  try {
    const userFavorites = await Favorite.findOne({ userId: req.userId });
    
    if (!userFavorites || userFavorites.productIds.length === 0) {
      return res.json([]);
    }
    
    const favoriteProducts = await Product.find({
      _id: { $in: userFavorites.productIds }
    });
    
    res.json(favoriteProducts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/favorites/:productId', verifyToken, async (req, res) => {
  try {
    const { productId } = req.params;
    
    // Verificar si el producto existe
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }
    
    // Buscar favorito del usuario o crear uno nuevo
    let userFavorites = await Favorite.findOne({ userId: req.userId });
    
    if (!userFavorites) {
      userFavorites = new Favorite({
        userId: req.userId,
        productIds: [productId]
      });
    } else if (!userFavorites.productIds.includes(productId)) {
      userFavorites.productIds.push(productId);
    } else {
      return res.status(400).json({ message: 'El producto ya está en favoritos' });
    }
    
    await userFavorites.save();
    
    // Enviar actualización por WebSocket
    sendUpdate('FAVORITE_ADDED', { 
      productId,
      product 
    }, 'favorites-updates', req.userId);
    
    res.json({ message: 'Producto agregado a favoritos' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.delete('/api/favorites/:productId', verifyToken, async (req, res) => {
  try {
    const { productId } = req.params;
    
    const userFavorites = await Favorite.findOne({ userId: req.userId });
    
    if (!userFavorites || !userFavorites.productIds.includes(productId)) {
      return res.status(400).json({ message: 'El producto no está en favoritos' });
    }
    
    userFavorites.productIds = userFavorites.productIds.filter(
      id => id.toString() !== productId
    );
    
    await userFavorites.save();
    
    // Enviar actualización por WebSocket
    sendUpdate('FAVORITE_REMOVED', { 
      productId 
    }, 'favorites-updates', req.userId);
    
    res.json({ message: 'Producto eliminado de favoritos' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Configuración de WebSocket para actualizaciones en tiempo real
const wss = new WebSocket.Server({ server });

// Almacenar conexiones activas
const clients = new Map();

// Manejar conexiones WebSocket
wss.on('connection', (ws, req) => {
  // Extraer token y canal de la URL
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  const channel = url.pathname.split('/')[1] || 'global-updates';
  
  if (!token) {
    ws.close(1008, 'Token no proporcionado');
    return;
  }
  
  // Verificar token
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    
    // Almacenar la conexión con su userId y canal
    if (!clients.has(userId)) {
      clients.set(userId, []);
    }
    
    clients.get(userId).push({
      ws,
      channel
    });
    
    console.log(`Cliente conectado a canal: ${channel}, userId: ${userId}`);
    
    // Enviar mensaje de confirmación
    ws.send(JSON.stringify({
      type: 'CONNECTION_ESTABLISHED',
      channel
    }));
    
    // Manejar mensajes entrantes
    ws.on('message', (message) => {
      console.log(`Mensaje recibido de ${userId}: ${message}`);
      try {
        const data = JSON.parse(message);
        // Aquí puedes manejar acciones específicas según los mensajes
      } catch (error) {
        console.error('Error al procesar mensaje:', error);
      }
    });
    
    // Manejar desconexión
    ws.on('close', () => {
      console.log(`Cliente desconectado: ${userId}, canal: ${channel}`);
      
      // Eliminar cliente de la lista
      if (clients.has(userId)) {
        const userConnections = clients.get(userId);
        const index = userConnections.findIndex(conn => conn.ws === ws);
        
        if (index !== -1) {
          userConnections.splice(index, 1);
          
          if (userConnections.length === 0) {
            clients.delete(userId);
          }
        }
      }
    });
  } catch (error) {
    console.error('Error de autenticación WebSocket:', error);
    ws.close(1008, 'Token inválido');
  }
});

// Función para enviar actualizaciones a los clientes
const sendUpdate = (type, data, channelFilter = null, excludeUserId = null) => {
  const message = JSON.stringify({
    type,
    ...data,
    timestamp: new Date().toISOString()
  });
  
  clients.forEach((connections, userId) => {
    // Excluir usuario específico si se solicitó
    if (excludeUserId && userId === excludeUserId) {
      return;
    }
    
    connections.forEach(({ ws, channel }) => {
      // Filtrar por canal si se especificó
      if (channelFilter && channel !== channelFilter) {
        return;
      }
      
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    });
  });
};

// Conectar a MongoDB y luego iniciar el servidor
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Conectado a MongoDB');
    server.listen(PORT, () => {
      console.log(`Servidor ejecutándose en el puerto ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Error al conectar con MongoDB:', err);
    process.exit(1);
  });