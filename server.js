// =============================================
//               SERVER.JS - PARTE 1 DE 3
// =============================================

// IMPORTACIONES Y CONFIGURACIÓN INICIAL
// =============================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const ejs = require('ejs');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fetch = require('node-fetch');




const app = express();
const PORT = process.env.PORT || 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

// =============================================
// CONEXIÓN A MONGODB
// =============================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tentacionpy_final_db')
  .then(() => console.log('✅ Conectado a MongoDB'))
  .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// =============================================
// CONFIGURACIÓN DE CLOUDINARY
// =============================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const getPublicId = (url) => {
    try {
        if (!url || !url.includes('cloudinary')) return null;
        const parts = url.split('/');
        const versionIndex = parts.findIndex(part => part.startsWith('v'));
        if (versionIndex === -1) return null;
        const publicIdWithFormat = parts.slice(versionIndex + 1).join('/');
        return publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));
    } catch (e) { console.error("Error extrayendo public_id:", e); return null; }
};

// ... (código anterior)

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: (req, file) => {
        // 1. Creamos el texto dinámico para la marca de agua
        const watermarkText = `${req.user.username} en TentacionPY.com`;

        // 2. Definimos la transformación para FOTOS (más pequeña y discreta)
        const imageTransformation = [{
            overlay: {
                font_family: "Arial",
                font_size: 45,       // ¡CAMBIO! Mucho más pequeño
                font_weight: "bold",
                text: watermarkText
            },
            color: "#FFFFFF",
            opacity: 60,
            gravity: "south",
            y: 25
        }];

        // 3. Definimos la transformación para VIDEOS (un poco más grande)
        const videoTransformation = [{
            overlay: {
                font_family: "Arial",
                font_size: 40,       // ¡CAMBIO! Un poquito más grande
                font_weight: "normal",
                text: watermarkText
            },
            color: "#FFFFFF",
            opacity: 60,
            gravity: "south_east",
            x: 20,
            y: 20
        }];

        // 4. Devolvemos la configuración completa
        return {
            folder: 'tentacionpy_final',
            resource_type: 'auto',
            allowed_formats: ['jpeg', 'png', 'jpg', 'mp4', 'mov', 'avi'],
            transformation: file.mimetype.startsWith('image/') ? imageTransformation : videoTransformation
        };
    }
});
const upload = multer({ storage });


// ... (código posterior)


// =============================================
// CONSTANTES Y MODELOS DE DATOS (ACTUALIZADOS)
// =============================================

const PAGOPAR_PUBLIC_TOKEN = "db3515375d0ac2ba2745b6355458c687";
const PAGOPAR_PRIVATE_TOKEN = "280e500fb8bc93cd782d7fa4435de2f8";
// Constantes que servirán como valores por defecto al iniciar la aplicación.
// Serán reemplazadas por la configuración de la base de datos en las rutas.
const CITIES = ['Asunción', 'Central', 'Ciudad del Este', 'Encarnación', 'Villarrica', 'Coronel Oviedo', 'Pedro Juan Caballero', 'Otra'];
const CATEGORIES = ['Acompañante', 'Masajes', 'OnlyFans', 'Contenido Digital', 'Shows', 'Otro'];

// Schemas
const donationSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, amount: Number }, { timestamps: true });
// DESPUÉS (Añadimos parentCommentId)
const commentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    donation: donationSchema,
    parentCommentId: { type: mongoose.Schema.Types.ObjectId, default: null } // ID del comentario al que se responde
}, { timestamps: true });const subscriptionSchema = new mongoose.Schema({ subscriberId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, endDate: Date }, { timestamps: true });
const userSubscriptionSchema = new mongoose.Schema({ creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, endDate: Date });


const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String }, googleId: { type: String },
    gender: { type: String, enum: ['Mujer', 'Hombre', 'Trans'] }, orientation: { type: String, enum: ['Heterosexual', 'Homosexual', 'Bisexual'] },
    location: { type: String, enum: CITIES }, bio: String, whatsapp: String, profilePic: { type: String, default: 'https://res.cloudinary.com/dmedd6w1q/image/upload/v1752519015/Gemini_Generated_Image_jafmcpjafmcpjafm_i5ptpl.png' },
    tpysBalance: { type: Number, default: 100 },
    isVerified: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },
    purchasedVideos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    likedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
    isAdmin: { type: Boolean, default: false },
    role: { type: String, enum: ['User', 'Moderator', 'Admin'], default: 'User' }, // <-- AÑADE O MODIFICA ESTA LÍNEA
    subscriptions: [userSubscriptionSchema],
    subscribers: [subscriptionSchema],
    subscriptionSettings: { isActive: { type: Boolean, default: false }, price: { type: Number, enum: [300, 600, 1000, 1250], default: 300 } },
    achievements: { tenSubscribers: { claimed: Boolean }, thousandFollowers: { claimed: Boolean }, tenVideoSales: { claimed: Boolean } },
    automatedChatMessage: { type: String, default: "¡Hola! Gracias por suscribirte. Pide tu video personalizado, ¡precios al privado!" },
    automatedMessageEnabled: { type: Boolean, default: true },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    securityQuestions: [{
        question: String,
        answer: String // Guardaremos el hash de la respuesta
    }] 
}, { timestamps: true });

// To: tpy.com/server.js
const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, type: { type: String, enum: ['image', 'video'] }, files: [String],
    description: String, whatsapp: String, category: { type: String, enum: CATEGORIES }, tags: [String], address: String, services: [String], rate: String,
    price: { type: Number, default: 0 }, salesCount: { type: Number, default: 0 }, isSubscriberOnly: { type: Boolean, default: false },
    views: { type: Number, default: 0 }, likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], comments: [commentSchema],
    boostedUntil: Date,
    boostOptions: { color: String, label: String },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' } // <-- LÍNEA AÑADIDA
}, { timestamps: true });

// To: tpy.com/server.js

// ===== NUEVO MODELO PARA SOLICITUDES DE VERIFICACIÓN =====
const verificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    idPhoto: { type: String, required: true },
    selfiePhoto: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    rejectionReason: { type: String }
}, { timestamps: true });

const Verification = mongoose.model('Verification', verificationSchema);

// tpy.com/server.js

const reportSchema = new mongoose.Schema({
    reportingUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reportedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reportedPostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
    // --- INICIO DE CÓDIGO AÑADIDO ---
    reportedMessageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    type: { type: String, enum: ['user', 'post', 'chat_message'], required: true },
    // --- FIN DE CÓDIGO AÑADIDO ---
    category: { type: String, required: true },
    reason: { type: String }, // Razón ya no es requerida
    status: { type: String, enum: ['pendiente', 'revisado'], default: 'pendiente' }
}, { timestamps: true });


// ===== MODELO DE TRANSACCIÓN ACTUALIZADO =====
const transactionSchema = new mongoose.Schema({
    type: { type: String, enum: ['video_purchase', 'subscription', 'donation', 'achievement_reward', 'boost', 'tpys_purchase', 'chat_tip', 'admin_adjustment'] }, // <-- NUEVO TIPO
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, 
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // <-- NUEVO CAMPO
    amount: Number, 
    netEarning: Number,
    description: { type: String }, // <-- NUEVO CAMPO para razón de ajuste
    currency: { type: String, enum: ['TPYS', 'PYG'], default: 'TPYS' },
    paymentGatewayId: String,
    status: { type: String, enum: ['PENDIENTE', 'COMPLETADO', 'CANCELADO'], default: 'COMPLETADO' }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, amount: Number, method: String,
    details: { fullName: String, ci: String, bankName: String, accountNumber: String, phone: String, alias: String },
    status: { type: String, enum: ['Pendiente', 'Procesado', 'Rechazado'], default: 'Pendiente' }
}, { timestamps: true });

const blockedUserSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    blockedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });


const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['like', 'comment', 'follow', 'subscribe', 'sale', 'donation', 'message', 'tip', 'admin'] },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, 
    isRead: { type: Boolean, default: false },
    message: String,
}, { timestamps: true });

// tpy.com/server.js

const manualDepositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true }, // Monto en Guaraníes que el usuario declara
    proofImageUrl: { type: String, required: true },
    status: { type: String, enum: ['Pendiente', 'Aprobado', 'Rechazado'], default: 'Pendiente' }
}, { timestamps: true });

const ManualDeposit = mongoose.model('ManualDeposit', manualDepositSchema);

// Archivo: tpy.com/server.js

const messageSchema = new mongoose.Schema({
    conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    tpysAmount: { type: Number, default: 0 },
    isRead: { type: Boolean, default: false },
    // --- ESTRUCTURA MODIFICADA (MÁS SIMPLE Y ROBUSTA) ---
    mediaUrl: String,
    mediaType: { type: String, enum: ['image', 'video'] }
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);
const Report = mongoose.model('Report', reportSchema);
const BlockedUser = mongoose.model('BlockedUser', blockedUserSchema);


// =============================================
// MIDDLEWARES Y PASSPORT (ACTUALIZADO)
// =============================================

// =============================================
// MODELO Y MIDDLEWARE PARA CONFIGURACIÓN DEL SITIO
// =============================================
const siteConfigSchema = new mongoose.Schema({
    // Usamos un ID fijo para asegurar que solo haya un documento de configuración
    configKey: { type: String, default: 'main_config', unique: true },
    verificationRequired: { type: Boolean, default: true },
    creatorEarningRate: { type: Number, default: 0.55, min: 0, max: 1 },
    cities: { type: [String], default: ['Asunción', 'Central', 'Ciudad del Este', 'Encarnación', 'Villarrica', 'Coronel Oviedo', 'Pedro Juan Caballero', 'Otra'] },
    categories: { type: [String], default: ['Acompañante', 'Masajes', 'OnlyFans', 'Contenido Digital', 'Shows', 'Otro'] },
    tpysPackages: [{
        tpys: Number,
        gs: Number,
        isPopular: Boolean
    }]
});

const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

// Middleware para cargar la configuración del sitio en cada request
app.use(async (req, res, next) => {
    try {
        let config = await SiteConfig.findOne({ configKey: 'main_config' });
        if (!config) {
            // Si no existe configuración, creamos una por defecto
            config = new SiteConfig();
            // Paquetes de TPYS por defecto
            config.tpysPackages = [
                { tpys: 100, gs: 10000, isPopular: false },
                { tpys: 300, gs: 30000, isPopular: false },
                { tpys: 600, gs: 60000, isPopular: false },
                { tpys: 1000, gs: 100000, isPopular: true },
                { tpys: 2000, gs: 200000, isPopular: false },
            ];
            await config.save();
        }
        res.locals.siteConfig = config;
        // Hacemos que las constantes ahora dependan de la configuración de la BD
        res.locals.CITIES = config.cities;
        res.locals.CATEGORIES = config.categories;
        res.locals.CREATOR_EARNING_RATE = config.creatorEarningRate;

        next();
    } catch (err) {
        // En caso de un error grave al cargar la configuración, pasamos el error
        next(err);
    }
});


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET || 'super-secret-key-12345', resave: false, saveUninitialized: true, cookie: { secure: 'auto' } }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// Helper para formatear fechas
const formatDate = (date) => {
    if (!date) return '';
    const d = new Date(date);
    const now = new Date();
    const diffSeconds = Math.round((now - d) / 1000);
    if (diffSeconds < 60) return 'Justo ahora';
    const diffMinutes = Math.round(diffSeconds / 60);
    if (diffMinutes < 60) return `Hace ${diffMinutes} min`;
    const diffHours = Math.round(diffMinutes / 60);
    if (diffHours < 24) return `Hace ${diffHours} h`;
    return d.toLocaleDateString('es-PY');
};

// Middleware global para variables locales
app.use(async (req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.formatDate = formatDate;
    res.locals.path = req.path;
    res.locals.query = req.query; // Para mantener los valores en los formularios de búsqueda
    if (req.user) {
        res.locals.unreadNotifications = await Notification.countDocuments({ userId: req.user._id, isRead: false });
    } else {
        res.locals.unreadNotifications = 0;
    }
    next();
});

// ===== LÓGICA DE LOGIN ACTUALIZADA PARA VERIFICAR BANEO =====
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || !user.password) return done(null, false, { message: 'Credenciales incorrectas.' });

        // VERIFICACIÓN DE BANEO
        if (user.isBanned) return done(null, false, { message: 'Esta cuenta ha sido suspendida.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Credenciales incorrectas.' });
        return done(null, user);
    } catch (err) { return done(err); }
}));

const CALLBACK_URL = `${process.env.BASE_URL || 'http://localhost:3000'}/auth/google/callback`;
passport.use(new GoogleStrategy({ clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: CALLBACK_URL },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            // VERIFICACIÓN DE BANEO EN LOGIN CON GOOGLE
            if (user.isBanned) return done(null, false, { message: 'Esta cuenta ha sido suspendida.' });
            if (!user.googleId) { user.googleId = profile.id; }
            await user.save();
            return done(null, user);
        }
        const newUser = new User({
            googleId: profile.id,
            username: profile.displayName.replace(/\s/g, '').toLowerCase() + Math.floor(Math.random() * 1000),
            email: profile.emails[0].value,
            profilePic: profile.photos[0].value,
            isVerified: false,
            gender: 'Mujer',
            orientation: 'Heterosexual'
        });
        await newUser.save();
        return done(null, newUser);
    } catch (err) { return done(err, null); }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { 
        const user = await User.findById(id); 
        done(null, user); 
    } catch (err) { 
        done(err); 
    }
});

// ===== MIDDLEWARE DE AUTENTICACIÓN ACTUALIZADO =====
const requireAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        // Si el usuario está autenticado, verifica si está baneado en cada request
        if (req.user.isBanned) {
            req.logout((err) => { // Desloguea al usuario baneado
                if(err) return next(err);
                // Aquí podrías añadir un mensaje flash si usas connect-flash
                res.status(403).render('error', { message: 'Tu cuenta ha sido suspendida. Contacta con el soporte.' });
            });
        } else {
            return next(); // Si no está baneado, continúa
        }
    } else {
        res.redirect('/login');
    }
};

const requireAdmin = (req, res, next) => (req.isAuthenticated() && req.user.isAdmin) ? next() : res.status(403).render('error', { message: "Acceso denegado. No tienes permisos de administrador." });

// En server.js, después de requireAdmin

const requireModerator = (req, res, next) => {
    if (req.isAuthenticated() && (req.user.role === 'Moderator' || req.user.isAdmin)) {
        return next();
    }
    res.status(403).render('error', { message: "Acceso denegado. No tienes permisos suficientes." });
};


// En tentacionpy/server.js, al inicio del archivo

// =============================================
// SEGUIMIENTO DE USUARIOS ACTIVOS
// =============================================
const activeSessions = {};
const ACTIVE_TIMEOUT_MINUTES = 5; // Un usuario se considera inactivo después de 5 minutos

// Limpieza periódica para eliminar sesiones inactivas
setInterval(() => {
    const now = Date.now();
    for (const sessionId in activeSessions) {
        if (now - activeSessions[sessionId] > ACTIVE_TIMEOUT_MINUTES * 60 * 1000) {
            delete activeSessions[sessionId];
        }
    }
}, 30 * 1000); // Se ejecuta cada 30 segundos

// En tentacionpy/server.js, después de app.use(passport.session());

// Middleware para actualizar la última actividad de una sesión
app.use((req, res, next) => {
    if (req.session.id) {
        activeSessions[req.session.id] = Date.now();
    }
    next();
});

// =============================================
// RUTAS PARA CONFIGURACIÓN DEL SITIO (ADMIN)
// =============================================
app.get('/privacy', (req, res) => res.render('privacy'));

app.get('/admin/settings', requireAdmin, (req, res, next) => {
    // La configuración ya está cargada en res.locals.siteConfig por el middleware
    res.render('admin/settings.html', { path: req.path });
});



app.post('/admin/settings', requireAdmin, async (req, res, next) => {
    try {
        // LA CORRECCIÓN ESTÁ AQUÍ: Añadimos 'verificationRequired' a la lista
        const { verificationRequired, creatorEarningRate, categories, cities, packages } = req.body;

        const config = await SiteConfig.findOne({ configKey: 'main_config' });

        // Ahora esta línea funcionará porque 'verificationRequired' ya existe
        config.verificationRequired = (verificationRequired === 'on');

        // El resto de la función sigue igual
        config.creatorEarningRate = parseFloat(creatorEarningRate) / 100;
        config.categories = categories.split(',').map(c => c.trim()).filter(Boolean);
        config.cities = cities.split(',').map(c => c.trim()).filter(Boolean);

        const updatedPackages = [];
        if (packages) {
            Object.values(packages).forEach(pkg => {
                if (pkg.tpys && pkg.gs) {
                    updatedPackages.push({
                        tpys: parseInt(pkg.tpys, 10),
                        gs: parseInt(pkg.gs, 10),
                        isPopular: pkg.isPopular === 'on'
                    });
                }
            });
        }
        config.tpysPackages = updatedPackages;

        await config.save();
        res.redirect('/admin/settings');
    } catch (err) {
        next(err);
    }
});



const isPostOwner = async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).render('error', { message: "Publicación no encontrada." });
        // El admin siempre tiene permisos
        if (!post.userId.equals(req.user._id) && !req.user.isAdmin) {
            return res.status(403).render('error', { message: "No tienes permiso para editar esta publicación." });
        }
        res.locals.post = post;
        next();
    } catch (err) { 
        console.error(err);
        res.status(500).render('error', { message: "Error al verificar permisos."});
    }
};













app.post('/manual-deposit', requireAuth, upload.single('proof'), async (req, res, next) => {
    try {
        const { amount } = req.body;
        if (!req.file) {
            throw new Error("Debes subir una imagen del comprobante.");
        }
        if (!amount || parseInt(amount) < 10000) {
             throw new Error("El monto mínimo para depósito manual es de 10.000 Gs.");
        }

        const newDeposit = new ManualDeposit({
            userId: req.user._id,
            amount: parseInt(amount),
            proofImageUrl: req.file.path,
            status: 'Pendiente'
        });

        await newDeposit.save();

        // Redirigimos a la misma página. Puedes agregar un mensaje de éxito si lo deseas.
        res.redirect('/add-funds');

    } catch (err) {
        next(err);
    }
});


// 3. AÑADE ESTAS RUTAS PARA LA GESTIÓN DEL ADMINISTRADOR
// =================================================================
app.get('/admin/deposits', requireAdmin, async (req, res, next) => {
    try {
        const deposits = await ManualDeposit.find({ status: 'Pendiente' })
            .populate('userId', 'username email')
            .sort({ createdAt: 'desc' });
        res.render('admin/deposits.html', { deposits: deposits, path: req.path });
    } catch (err) {
        next(err);
    }
});

app.post('/admin/deposit/:id/update', requireAdmin, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const { status, verifiedAmount } = req.body;
            const deposit = await ManualDeposit.findById(req.params.id).session(session);
            if (!deposit || deposit.status !== 'Pendiente') {
                throw new Error('Depósito no encontrado o ya procesado.');
            }

            if (status === 'Aprobado') {
                const amountGs = parseInt(verifiedAmount);
                if (isNaN(amountGs) || amountGs <= 0) {
                    throw new Error('El monto verificado no es válido.');
                }
                const tpysToCredit = Math.floor(amountGs / 100);
                
                await User.findByIdAndUpdate(deposit.userId, { $inc: { tpysBalance: tpysToCredit } }, { session });
                
                deposit.status = 'Aprobado';
                await deposit.save({ session });

                await new Notification({
                    userId: deposit.userId,
                    type: 'admin',
                    message: `Tu depósito de ${amountGs.toLocaleString('es-PY')} Gs. fue aprobado. Se acreditaron ${tpysToCredit} TPYS a tu cuenta.`
                }).save({ session });

            } else if (status === 'Rechazado') {
                deposit.status = 'Rechazado';
                await deposit.save({ session });

                await new Notification({
                    userId: deposit.userId,
                    type: 'admin',
                    message: `Tu solicitud de depósito manual fue rechazada. Contacta a soporte si crees que es un error.`
                }).save({ session });
            }
        });
        res.redirect('/admin/deposits');
    } catch (err) {
        next(err);
    } finally {
        await dbSession.endSession();
    }
});






// En tentacionpy/server.js, junto a las otras rutas de /admin/...

app.get('/admin/active-users', requireAdmin, (req, res) => {
    const count = Object.keys(activeSessions).length;
    res.json({ activeUsers: count });
});

// To: tpy.com/server.js

const requireVerification = async (req, res, next) => {
    // Obtenemos la configuración directamente de res.locals
    const config = res.locals.siteConfig;

    // Si la verificación NO es requerida, o si el usuario ya está verificado o es admin, puede pasar.
    if (!config.verificationRequired || req.user.isVerified || req.user.isAdmin) {
        return next();
    }
    // Si no, lo mandamos a la página de verificación.
    res.redirect('/verify-account');
};

// =============================================
//               FIN DE LA PARTE 1
// =============================================

// RUTA PARA LA PÁGINA DE CANCELACIÓN DE SUSCRIPCIÓN
app.get('/cancel-subscription/:creatorId', requireAuth, async (req, res, next) => {
    try {
        const creator = await User.findById(req.params.creatorId);
        if (!creator) {
            return res.status(404).render('error', { message: 'Creador no encontrado.' });
        }
        
        // Aquí deberías añadir la lógica para generar el link de cancelación de Pagopar.
        // Por ahora, solo renderizamos la página con la información.
        
        res.render('cancel-subscription', { creator });

    } catch (err) {
        next(err);
    }
});


// --- RUTAS DE SEGURIDAD MEJORADAS ---

// MUESTRA LA PÁGINA DE SEGURIDAD (AHORA VERIFICA SI EL USUARIO TIENE CONTRASEÑA)
app.get('/settings/security', requireAuth, (req, res) => {
    res.render('settings/security.html', { 
        error: null, 
        success: null,
        hasPassword: !!req.user.password // Envía 'true' si el usuario tiene contraseña, 'false' si no (usuario de Google)
    });
});

// GUARDA LAS PREGUNTAS DE SEGURIDAD
app.post('/settings/security', requireAuth, async (req, res, next) => {
    try {
        const { question1, answer1, question2, answer2, password } = req.body;
        const user = await User.findById(req.user._id);

        if (!user.password) {
            return res.render('settings/security.html', { error: 'Primero debes crear una contraseña para tu cuenta.', success: null, hasPassword: false });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('settings/security.html', { error: 'La contraseña actual es incorrecta.', success: null, hasPassword: true });
        }

        const hashedAnswer1 = await bcrypt.hash(answer1.toLowerCase().trim(), 10);
        const hashedAnswer2 = await bcrypt.hash(answer2.toLowerCase().trim(), 10);

        user.securityQuestions = [
            { question: question1, answer: hashedAnswer1 },
            { question: question2, answer: hashedAnswer2 }
        ];
        await user.save();
        
        res.render('settings/security.html', { success: '¡Tus preguntas de seguridad se han actualizado correctamente!', error: null, hasPassword: true });

    } catch (err) { next(err); }
});

// RUTA NUEVA PARA QUE USUARIOS DE GOOGLE CREEN SU CONTRASEÑA
app.post('/settings/create-password', requireAuth, async (req, res, next) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        const user = await User.findById(req.user._id);

        if (user.password) {
            return res.redirect('/settings/security'); // Si ya tiene contraseña, no hace nada
        }
        if (newPassword !== confirmPassword) {
            return res.render('settings/security.html', { error: 'Las contraseñas no coinciden.', success: null, hasPassword: false });
        }
        if (newPassword.length < 6) {
             return res.render('settings/security.html', { error: 'La contraseña debe tener al menos 6 caracteres.', success: null, hasPassword: false });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.render('settings/security.html', { success: '¡Contraseña creada con éxito! Ahora puedes configurar tus preguntas de seguridad.', error: null, hasPassword: true });

    } catch (err) { next(err); }
});

// RUTA NUEVA PARA ELIMINAR LA CUENTA DE USUARIO
app.post('/settings/delete-account', requireAuth, async (req, res, next) => {
    try {
        const { password } = req.body;
        const user = await User.findById(req.user._id);

        if (!user.password) {
             return res.render('settings/security.html', { error: 'Debes crear una contraseña antes de poder eliminar tu cuenta.', success: null, hasPassword: false });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('settings/security.html', { error: 'La contraseña es incorrecta. No se ha eliminado la cuenta.', success: null, hasPassword: true });
        }
        
        // --- PROCESO DE ELIMINACIÓN ---
        // Eliminar posts y archivos de Cloudinary
        const userPosts = await Post.find({ userId: user._id });
        for (const post of userPosts) {
            for (const fileUrl of post.files) {
                const publicId = getPublicId(fileUrl);
                if (publicId) await cloudinary.uploader.destroy(publicId, { resource_type: fileUrl.includes('.mp4') ? 'video' : 'image' });
            }
        }
        await Post.deleteMany({ userId: user._id });
        
        // Eliminar foto de perfil de Cloudinary
        if (user.profilePic && !user.profilePic.includes('default.png')) {
             const publicId = getPublicId(user.profilePic);
             if (publicId) await cloudinary.uploader.destroy(publicId);
        }
        
        // Eliminar al usuario de la base de datos
        await User.findByIdAndDelete(user._id);

        // Cerrar sesión
        req.logout((err) => {
            if (err) return next(err);
            res.redirect('/');
        });

    } catch (err) { next(err); }
});



// --- RUTAS PARA RECUPERACIÓN DE CONTRASEÑA ---

// PASO 1: Mostrar formulario para pedir email
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: null });
});

// PASO 2: Buscar usuario y redirigir a las preguntas
app.post('/forgot-password', async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email.toLowerCase() });
        if (!user || !user.securityQuestions || user.securityQuestions.length < 2) {
            return res.render('forgot-password', { error: 'El usuario no existe o no ha configurado sus preguntas de seguridad.' });
        }
        
        // Guardar el ID del usuario en la sesión para el siguiente paso
        req.session.resetUserId = user._id;
        res.redirect('/reset-password');

    } catch (err) {
        next(err);
    }
});

// PASO 3: Mostrar las preguntas y el formulario para la nueva contraseña
app.get('/reset-password', async (req, res, next) => {
    try {
        if (!req.session.resetUserId) {
            return res.redirect('/forgot-password');
        }
        const user = await User.findById(req.session.resetUserId);
        if (!user) {
             return res.redirect('/forgot-password');
        }

        res.render('reset-password', {
            error: null,
            userId: user._id,
            question1: user.securityQuestions[0].question,
            question2: user.securityQuestions[1].question
        });
    } catch (err) {
        next(err);
    }
});

// PASO 4: Validar respuestas y actualizar contraseña
app.post('/reset-password', async (req, res, next) => {
    try {
        const { userId, answer1, answer2, newPassword } = req.body;

        // Comprobar que seguimos en la misma sesión de reseteo
        if (req.session.resetUserId !== userId) {
            return res.redirect('/login');
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.redirect('/login');
        }

        const isAnswer1Match = await bcrypt.compare(answer1.toLowerCase().trim(), user.securityQuestions[0].answer);
        const isAnswer2Match = await bcrypt.compare(answer2.toLowerCase().trim(), user.securityQuestions[1].answer);

        if (!isAnswer1Match || !isAnswer2Match) {
            return res.render('reset-password', {
                error: 'Una o más respuestas son incorrectas.',
                userId: user._id,
                question1: user.securityQuestions[0].question,
                question2: user.securityQuestions[1].question
            });
        }
        
        // Si las respuestas son correctas, hashear y guardar la nueva contraseña
        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();

        // Limpiar la sesión para que no se pueda reusar
        delete req.session.resetUserId;

        // Redirigir al login con un mensaje de éxito (esto requiere connect-flash, pero por ahora solo redirigimos)
        res.redirect('/login');

    } catch (err) {
        next(err);
    }
});


// =============================================================
// FUNCIÓN AUTOMÁTICA PARA ELIMINAR DOCUMENTOS DE VERIFICACIÓN ANTIGUOS
// =============================================================
const deleteOldVerifications = async () => {
    console.log('🧹 Ejecutando tarea de limpieza de verificaciones antiguas...');
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

    try {
        // Busca verificaciones aprobadas o rechazadas que tengan más de 90 días
        const oldVerifications = await Verification.find({
            status: { $in: ['approved', 'rejected'] },
            createdAt: { $lt: ninetyDaysAgo }
        });

        if (oldVerifications.length === 0) {
            console.log('✅ No se encontraron verificaciones antiguas para eliminar.');
            return;
        }

        console.log(`🗑️ Se encontraron ${oldVerifications.length} verificaciones para eliminar.`);

        for (const verification of oldVerifications) {
            // Eliminar archivos de Cloudinary
            if (verification.idPhoto) {
                const idPhotoPublicId = getPublicId(verification.idPhoto);
                if (idPhotoPublicId) await cloudinary.uploader.destroy(idPhotoPublicId);
            }
            if (verification.selfiePhoto) {
                const selfiePhotoPublicId = getPublicId(verification.selfiePhoto);
                if (selfiePhotoPublicId) await cloudinary.uploader.destroy(selfiePhotoPublicId);
            }
            
            // Eliminar el registro de la base de datos
            await Verification.findByIdAndDelete(verification._id);
        }
        console.log('✅ Tarea de limpieza completada con éxito.');

    } catch (err) {
        console.error('❌ Error durante la limpieza de verificaciones antiguas:', err);
    }
};

// Ejecuta la tarea una vez al iniciar el servidor
deleteOldVerifications();

// Y luego, la ejecuta cada 24 horas
setInterval(deleteOldVerifications, 24 * 60 * 60 * 1000);


// RUTA PARA LA PÁGINA DE CONSEJOS PARA CREADORES
app.get('/creator-tips', (req, res) => {
    res.render('creator-tips');
});
// =============================================
//               SERVER.JS - PARTE 2 DE 3 (VERSIÓN COMPLETA)
// =============================================

// RUTAS PRINCIPALES Y DE PERFIL
// =============================================
app.get('/', (req, res) => res.redirect('/feed'));

// RUTA /feed FINAL Y CORREGIDA
// Línea 372
app.get('/feed', async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 12;
        const { search_type = 'all', q, category, location, gender } = req.query;

        // ... dentro de app.get('/feed', ...)

let results = [];
let totalItems = 0;
let query = {};
// Condición base para no mostrar usuarios baneados
let activeUserCondition = { isBanned: { $ne: true } };

// --- LÓGICA DE USUARIOS BLOQUEADOS (EXISTENTE Y CORRECTA) ---
if (req.user) {
    const currentUser = await User.findById(req.user._id).select('blockedUsers');
    const usersBlockingCurrentUser = await User.find({ blockedUsers: req.user._id }).select('_id');
    const blockedIds = [
        ...(currentUser.blockedUsers || []),
        ...usersBlockingCurrentUser.map(u => u._id)
    ];
    if (blockedIds.length > 0) {
        activeUserCondition._id = { $nin: blockedIds };
    }
}

// --- INICIO DE LA LÓGICA CORREGIDA ---
if (search_type === 'users') {
    // Si la búsqueda es de usuarios, aplicamos los filtros directamente
    query = { ...activeUserCondition };
    if (q) query.username = { $regex: q, $options: 'i' };
    if (location) query.location = location;
    if (gender) query.gender = gender;

    totalItems = await User.countDocuments(query);
    results = await User.find(query)
        .sort({ createdAt: -1 })
        .skip((page - 1) * itemsPerPage)
        .limit(itemsPerPage);

} else {
    // Si la búsqueda es de ANUNCIOS o VIDEOS
    // 1. Primero, filtramos los CREADORES según los criterios de perfil (género, ubicación)
    const creatorQuery = { ...activeUserCondition };
    if (gender) creatorQuery.gender = gender;
    if (location) creatorQuery.location = location;

    // Obtenemos los IDs de los creadores que cumplen con los filtros
    const userIds = await User.find(creatorQuery).select('_id');

    // 2. Ahora, construimos la consulta para los POSTS
    query = { userId: { $in: userIds.map(u => u._id) }, status: 'approved' };

    // Aplicamos los filtros restantes (texto, categoría, etc.)
    if (q) {
        const regex = { $regex: q, $options: 'i' };
        query.$or = [{ description: regex }, { tags: regex }];
    }
    if (category) query.category = category;

    // ...
if (search_type === 'videos') {
    query.type = 'video'; // Solo videos
} else if (search_type === 'posts') {
    query.type = 'image'; // Solo anuncios (imágenes)
} else if (search_type === 'all') {
    // Para 'Todos', no añadimos filtro de tipo, por lo que traerá tanto 'image' como 'video'.
}
// ...

    totalItems = await Post.countDocuments(query);
    results = await Post.find(query)
        .populate({ path: 'userId', match: activeUserCondition }) // Populate para obtener info del creador
        .sort({ boostedUntil: -1, createdAt: -1 })
        .skip((page - 1) * itemsPerPage)
        .limit(itemsPerPage);
    
    // Filtro final para asegurar que no se muestren posts de usuarios bloqueados
    results = results.filter(p => p.userId);
}
// --- FIN DE LA LÓGICA CORREGIDA ---

        const totalPages = Math.ceil(totalItems / itemsPerPage);
        res.render('index', {
            results,
            resultType: search_type,
            currentPage: page,
            totalPages
        });

    } catch (err) {
        console.error("Error en /feed:", err);
        next(err);
    }
});

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res, next) => {
    try {
        const { username, email, password, gender, orientation, location, ageCheck } = req.body;
        if (!ageCheck) throw new Error("Debes confirmar que eres mayor de edad.");
        if (!password) throw new Error("La contraseña es requerida.");
        const existingUser = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
        if (existingUser) throw new Error('El email o nombre de usuario ya está en uso.');
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Esta línea es la clave: trae la configuración a esta función.
        const config = res.locals.siteConfig;

        const user = new User({
            username,
            email,
            password: hashedPassword,
            gender,
            orientation,
            location,
            // ASEGÚRATE DE QUE ESTA LÍNEA SEA EXACTAMENTE ASÍ:
            isVerified: !config.verificationRequired 
        });

        await user.save();
        req.login(user, (err) => { 
            if (err) return next(err); 
            res.redirect('/feed'); 
        });
    } catch (err) { 
        // Asegúrate de que los errores se muestren en la página de registro
        res.render('register', { error: err.message, CITIES: res.locals.CITIES }); 
    }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', passport.authenticate('local', { successRedirect: '/feed', failureRedirect: '/login' }));

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy(() => res.redirect('/'));
    });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/feed'));

app.get('/profile', requireAuth, (req, res) => res.redirect(`/user/${req.user.username}`));

app.get('/user/:username', async (req, res, next) => {
    try {
        const userProfile = await User.findOne({ username: req.params.username.toLowerCase() });

        if (!userProfile || userProfile.isBanned) {
            return res.status(404).render('error', { message: 'Usuario no encontrado o suspendido.' });
        }

        if (req.user) {
            const isBlockedByProfile = userProfile.blockedUsers.includes(req.user._id);
            const isBlockingProfile = req.user.blockedUsers.includes(userProfile._id);

            if(isBlockedByProfile || isBlockingProfile) {
                 return res.render('profile-blocked', { username: userProfile.username });
            }
        }

        const postQuery = { userId: userProfile._id, status: 'approved' };
        if (req.user && req.user._id.equals(userProfile._id)) {
            delete postQuery.status; // El dueño ve todos sus posts
        }

        const posts = await Post.find(postQuery).sort({ createdAt: -1 });
        let isSubscribed = false;
        if (req.user) {
            isSubscribed = !!req.user.subscriptions.find(s => s.creatorId.equals(userProfile._id) && new Date(s.endDate) > new Date());
        }

        const viewToRender = req.user && req.user._id.equals(userProfile._id) ? 'profile' : 'user-profile';
        res.render(viewToRender, { userProfile, posts, isSubscribed });
    } catch (err) {
        next(err);
    }
});

app.post('/user/:id/follow', requireAuth, async (req, res, next) => {
    try {
        const userToFollow = await User.findById(req.params.id);
        if (!userToFollow || req.user._id.equals(userToFollow._id)) return res.redirect('back');
        const currentUser = await User.findById(req.user._id);
        const isFollowing = currentUser.following.some(id => id.equals(userToFollow._id));
        if (isFollowing) {
            await User.findByIdAndUpdate(currentUser._id, { $pull: { following: userToFollow._id } });
            await User.findByIdAndUpdate(userToFollow._id, { $pull: { followers: currentUser._id } });
        } else {
            await User.findByIdAndUpdate(currentUser._id, { $addToSet: { following: userToFollow._id } });
            await User.findByIdAndUpdate(userToFollow._id, { $addToSet: { followers: currentUser._id } });
            await new Notification({ userId: userToFollow._id, actorId: currentUser._id, type: 'follow', message: 'ha comenzado a seguirte.' }).save();
        }
        res.redirect('back');
    } catch (err) { next(err); }
});


app.get('/faq', (req, res) => {
    res.render('faq.html');
});

// =============================================
// RUTAS DE POSTS Y CONTENIDO
// =============================================
// To: tpy.com/server.js
app.get('/new-post', requireAuth, requireVerification, (req, res) => res.render('new-post'));

app.post('/new-post', requireAuth, requireVerification, upload.array('files', 10), async (req, res, next) => {
    try {
        const { type, description, price, services, rate, address, whatsapp, category, tags, isSubscriberOnly } = req.body;
        if (!req.files || req.files.length === 0) throw new Error("Debes subir al menos un archivo.");
        const newPost = new Post({
            userId: req.user._id, type, files: req.files.map(f => f.path), description, whatsapp: whatsapp || req.user.whatsapp, category,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            price: type === 'video' && !(isSubscriberOnly === 'on') ? parseFloat(price) : 0,
            services: type === 'image' && services ? services.split(',').map(s => s.trim()) : [],
            rate: type === 'image' ? rate : '', address: type === 'image' ? address : '',
            isSubscriberOnly: isSubscriberOnly === 'on'
        });
        await newPost.save();
        res.redirect(`/anuncio/${newPost._id}`);
    } catch (err) { next(err); }
});

app.get('/anuncio/:id', async (req, res, next) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
            .populate({ path: 'userId', match: { isBanned: { $ne: true } } })
            .populate({ path: 'comments', populate: { path: 'userId', select: 'username profilePic' } });

        if (!post || !post.userId) return res.status(404).render('error', { message: 'Este contenido ya no está disponible.' });
        // DESPUÉS
const recommendedPosts = await Post.aggregate([
    { $match: { _id: { $ne: post._id }, category: post.category, status: 'approved' } },
    { $sample: { size: 12 } },
    { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'userId' } },
    { $unwind: '$userId' }
]);
        let canView = false; 
        let isOwner = false;
        let hasPurchased = false;
        let hasSubscriptionAccess = false;

        const isPaidContent = post.type === 'video' && (post.price > 0 || post.isSubscriberOnly);

        if (!isPaidContent) {
            
            canView = true;
        }

        if (req.user) {
            isOwner = post.userId.equals(req.user._id);
            hasPurchased = req.user.purchasedVideos.includes(post._id);
            const sub = req.user.subscriptions.find(s => s.creatorId.equals(post.userId._id) && new Date(s.endDate) > new Date());
            hasSubscriptionAccess = post.isSubscriberOnly && !!sub;

            // Si el usuario es el dueño, admin, ha comprado el video o está suscrito (si aplica), puede verlo.
            if (isOwner || req.user.isAdmin || hasPurchased || hasSubscriptionAccess) {
                canView = true;
            }
        }
        // --- FIN DE LA LÓGICA CORREGIDA ---

        res.render('anuncio-detail', { post, canView, isOwner, hasPurchased, hasSubscriptionAccess, recommendedPosts });
    } catch (err) {
        next(err);
    }
});

app.post('/post/:id/delete', requireAuth, isPostOwner, async (req, res, next) => {
    try {
        const post = res.locals.post;
        for (const fileUrl of post.files) {
            const publicId = getPublicId(fileUrl);
            if (publicId) await cloudinary.uploader.destroy(publicId, { resource_type: fileUrl.includes('/video/') ? 'video' : 'image' }).catch(err => console.log("Cloudinary destroy failed:", err));
        }
        await Post.findByIdAndDelete(req.params.id);
        const redirectUrl = req.originalUrl.includes('/admin') ? '/admin/posts' : '/profile';
        res.json({ success: true, redirectUrl });
    } catch (err) { next(err); }
});

// ===========================================
// RUTA DE LIKE - VERSIÓN FINAL Y CORRECTA
// ===========================================
app.post('/post/:id/like', requireAuth, async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ success: false, message: "Publicación no encontrada." });
        }

        const currentUser = await User.findById(req.user._id);
        const isLiked = currentUser.likedPosts.includes(post._id);

        if (isLiked) {
            // Quitar Like
            await User.findByIdAndUpdate(currentUser._id, { $pull: { likedPosts: post._id } });
            await Post.findByIdAndUpdate(post._id, { $pull: { likes: currentUser._id } });
        } else {
            // Dar Like
            await User.findByIdAndUpdate(currentUser._id, { $addToSet: { likedPosts: post._id } });
            await Post.findByIdAndUpdate(post._id, { $addToSet: { likes: currentUser._id } });
        }
        
        const updatedPost = await Post.findById(req.params.id); // Volver a leer para el conteo actualizado

        res.json({
            success: true,
            likes: updatedPost.likes.length,
            liked: !isLiked // El nuevo estado es el opuesto al anterior
        });

    } catch (err) {
        console.error("Error en la ruta de like:", err);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// DESPUÉS (añadimos parentCommentId al destructuring)
// RUTA DE COMENTARIOS MEJORADA PARA ACEPTAR RESPUESTAS
app.post('/post/:id/comments', requireAuth, async (req, res) => {
    const { text, donationAmount, parentCommentId } = req.body; // <-- AÑADIMOS parentCommentId
    const dbSession = await mongoose.startSession();
    try {
        let populatedComment;
        await dbSession.withTransaction(async (session) => {
            const CREATOR_EARNING_RATE = res.locals.siteConfig.creatorEarningRate; 
            const post = await Post.findById(req.params.id).session(session);
            if (!post) throw new Error("Post no encontrado");
            const commenter = await User.findById(req.user._id).session(session);
            const amount = Number(donationAmount) || 0;
            if (amount > 0 && commenter.tpysBalance < amount) throw new Error("No tienes suficientes TPYS para donar.");

            // Creamos el objeto del nuevo comentario
            const newCommentData = {
                userId: commenter._id,
                text,
                parentCommentId: parentCommentId || null // Guarda el ID del padre si existe
            };
            
            // Lógica de donación (sin cambios)
            if (amount > 0) {
                const isSelfDonation = commenter._id.equals(post.userId);
                const netEarning = amount * CREATOR_EARNING_RATE;
                if (isSelfDonation) {
                    commenter.tpysBalance = commenter.tpysBalance - amount + netEarning;
                    await commenter.save({ session });
                    await new Transaction({ type: 'donation', sellerId: commenter._id, buyerId: commenter._id, postId: post._id, amount, netEarning }).save({ session });
                } else {
                    const creator = await User.findById(post.userId).session(session);
                    if (!creator) throw new Error("Creador no encontrado.");
                    commenter.tpysBalance -= amount;
                    creator.tpysBalance += netEarning;
                    await commenter.save({ session });
                    await creator.save({ session });
                    await new Transaction({ type: 'donation', sellerId: creator._id, buyerId: commenter._id, postId: post._id, amount, netEarning }).save({ session });
                    await new Notification({ userId: creator._id, actorId: commenter._id, type: 'donation', postId: post._id, message: `te donó ${amount} TPYS en tu post.` }).save({ session });
                }
                newCommentData.donation = { userId: commenter._id, amount };
            }

            post.comments.push(newCommentData);
            await post.save({ session });
            
            if (!post.userId.equals(commenter._id)) {
                await new Notification({ userId: post.userId, actorId: commenter._id, type: 'comment', postId: post._id, message: `comentó tu post.` }).save({ session });
            }

            // Populamos el comentario para devolverlo al frontend
            await post.populate({ path: 'comments.userId', select: 'username profilePic' });
            populatedComment = post.comments.slice(-1)[0];
        });
        
        res.status(200).json({ success: true, comment: populatedComment });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message || 'Error interno del servidor.' });
    } finally {
        await dbSession.endSession();
    }
});

// =============================================
// RUTAS DE PÁGINAS ESTÁTICAS Y DE USUARIO
// =============================================
app.get('/my-videos', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({ path: 'purchasedVideos', populate: { path: 'userId', select: 'username profilePic' } });
        res.render('my-videos', { videos: user.purchasedVideos });
    } catch (err) { next(err); }
});

app.get('/my-likes', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({ path: 'likedPosts', populate: { path: 'userId', select: 'username profilePic' } });
        res.render('my-likes', { posts: user.likedPosts });
    } catch (err) { next(err); }
});

app.get('/notifications', requireAuth, async (req, res, next) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id }).populate('actorId', 'username profilePic').populate('postId', 'description type files').sort({ createdAt: -1 });
        await Notification.updateMany({ userId: req.user._id, isRead: false }, { $set: { isRead: true } });
        res.render('notifications', { notifications });
    } catch (err) { next(err); }
});

app.get('/terms', (req, res) => res.render('terms'));
app.get('/payout-info', requireAuth, (req, res) => res.render('payout-info'));



// =============================================
// NUEVAS RUTAS PARA LISTAS, BLOQUEO Y REPORTES
// =============================================

// --- LISTA DE SUSCRIPCIONES ---
// --- LISTA DE SUSCRIPCIONES (CORREGIDO)---
app.get('/my-subscriptions', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({
            path: 'subscriptions.creatorId',
            model: 'User'
        });

        // FILTRO AÑADIDO: Se asegura de que el creador exista antes de mostrarlo
        const activeSubscriptions = user.subscriptions
            .filter(s => s.creatorId) 
            .filter(s => new Date(s.endDate) > new Date());

        res.render('list-subscriptions.html', { subscriptions: activeSubscriptions });
    } catch (err) {
        next(err);
    }
});

// --- LISTA DE SEGUIDORES Y SEGUIDOS ---
app.get('/user/:username/list/:type', requireAuth, async (req, res, next) => {
    try {
        const { username, type } = req.params;
        const profileUser = await User.findOne({ username });
        if (!profileUser) return res.status(404).render('error', { message: 'Usuario no encontrado.' });

        const validTypes = ['followers', 'following'];
        if (!validTypes.includes(type)) return res.redirect(`/user/${username}`);

        const list = await User.find({ _id: { $in: profileUser[type] } });

        res.render('followers', {
            title: type === 'followers' ? 'Seguidores' : 'Siguiendo',
            user: profileUser,
            list: list
        });
    } catch (err) {
        next(err);
    }
});

// --- BLOQUEAR USUARIO ---
// --- RUTA DE BLOQUEO CORREGIDA Y MEJORADA ---
app.post('/user/:id/block', requireAuth, async (req, res, next) => {
    try {
        const userToBlockId = req.params.id;
        const currentUser = await User.findById(req.user._id);
        const userToBlock = await User.findById(userToBlockId);

        // Validar que los usuarios existan y no se esté bloqueando a sí mismo
        if (!userToBlock || currentUser._id.equals(userToBlockId)) {
            return res.status(400).json({ success: false, message: "Acción no válida." });
        }

        const blockIndex = currentUser.blockedUsers.indexOf(userToBlockId);

        if (blockIndex > -1) {
            // --- Lógica para DESBLOQUEAR ---
            currentUser.blockedUsers.splice(blockIndex, 1);
        } else {
            // --- Lógica para BLOQUEAR ---
            currentUser.blockedUsers.addToSet(userToBlockId);

            // Forzar que dejen de seguirse mutuamente
            currentUser.following.pull(userToBlockId);
            userToBlock.followers.pull(currentUser._id);
            
            currentUser.followers.pull(userToBlockId);
            userToBlock.following.pull(currentUser._id);
        }

        // Guardar los cambios en ambos documentos de usuario
        await currentUser.save();
        await userToBlock.save();

        // Refrescar la sesión del usuario para que los cambios se apliquen inmediatamente
        req.login(currentUser, (err) => {
            if (err) {
                return next(err);
            }
            // Responder con éxito. El frontend se encargará de recargar la página.
            return res.json({ success: true, redirectUrl: req.get('Referrer') || '/feed' });
        });

    } catch (err) {
        console.error("Error al bloquear/desbloquear usuario:", err);
        next(err);
    }
});

// --- VISTA DE USUARIOS BLOQUEADOS (CORREGIDO) ---
app.get('/settings/blocked', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate('blockedUsers');
        // Se corrige la ruta para que coincida con tu archivo: views/settings/blocked-user.html
        res.render('settings/blocked-user', { blockedUsers: user.blockedUsers });
    } catch (err) {
        next(err);
    }
});


// --- FORMULARIO DE REPORTE ---
app.get('/report', requireAuth, (req, res) => {
    const { type, id } = req.query;
    res.render('report-form', {
        type, id,
        REPORT_CATEGORIES: ['Contenido inapropiado', 'Spam', 'Acoso', 'Estafa o Fraude', 'Otro']
    });
});

// --- PROCESAR REPORTE ---
app.post('/report', requireAuth, async (req, res, next) => {
    try {
        const { type, id, category, reason } = req.body;
        const report = new Report({
            reportingUserId: req.user._id,
            type,
            category,
            reason
        });

        if (type === 'user') {
            report.reportedUserId = id;
        } else if (type === 'post') {
            report.reportedPostId = id;
        } else if (type === 'chat_message') { // <--- AÑADIR ESTA CONDICIÓN
            report.reportedMessageId = id;
        }

        await report.save();
        res.render('report-success');
    } catch (err) {
        next(err);
    }
});


// --- VISTA DE ADMIN PARA REPORTES ---
app.get('/admin/reports', requireModerator, async (req, res, next) => {
    try {
        const reports = await Report.find({ status: 'pendiente' })
            .populate('reportingUserId', 'username')
            .populate('reportedUserId', 'username')
            .populate('reportedPostId', '_id')
            // --- INICIO DEL CÓDIGO AÑADIDO ---
            .populate({
                path: 'reportedMessageId',
                select: 'mediaUrl mediaType senderId', // Obtenemos la media y quién la envió
                populate: {
                    path: 'senderId', // Obtenemos los datos del que envió el mensaje
                    select: 'username _id'
                }
            })
            // --- FIN DEL CÓDIGO AÑADIDO ---
            .sort({ createdAt: -1 });

        res.render('admin/reports.html', { reports, path: req.path });
    } catch (err) {
        next(err);
    }
});

// --- ACTUALIZAR ESTADO DE REPORTE ---
app.post('/admin/report/:id/update', requireModerator, async (req, res, next) => {
    try {
        await Report.findByIdAndUpdate(req.params.id, { status: 'revisado' });
        res.redirect('/admin/reports');
    } catch (err) {
        next(err);
    }
});


// --- INICIO: NUEVA RUTA PARA ELIMINAR CONTENIDO REPORTADO ---
app.post('/admin/report/:id/delete-content', requireModerator, async (req, res, next) => {
    try {
        const report = await Report.findById(req.params.id)
            .populate('reportedPostId')
            .populate('reportedMessageId');

        if (!report) {
            throw new Error('Reporte no encontrado.');
        }

        // Caso 1: El contenido reportado es un ANUNCIO
        if (report.type === 'post' && report.reportedPostId) {
            const post = report.reportedPostId;
            // Eliminar archivos de Cloudinary
            for (const fileUrl of post.files) {
                const publicId = getPublicId(fileUrl);
                if (publicId) {
                    const resourceType = fileUrl.includes('.mp4') || fileUrl.includes('.mov') ? 'video' : 'image';
                    await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
                }
            }
            // Eliminar el post de la base de datos
            await Post.findByIdAndDelete(post._id);
        }
        // Caso 2: El contenido reportado es un MENSAJE DE CHAT
        else if (report.type === 'chat_message' && report.reportedMessageId) {
            const message = report.reportedMessageId;
            // Eliminar el archivo de Cloudinary si existe
            if (message.mediaUrl) {
                const publicId = getPublicId(message.mediaUrl);
                if (publicId) {
                    const resourceType = message.mediaType === 'video' ? 'video' : 'image';
                    await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
                }
            }
            // Eliminar el mensaje de la base de datos
            await Message.findByIdAndDelete(message._id);
        }

        // Marcar el reporte como revisado después de eliminar el contenido
        report.status = 'revisado';
        await report.save();

        res.redirect('/admin/reports');

    } catch (err) {
        next(err);
    }
});
// --- FIN: NUEVA RUTA ---


// To: tpy.com/server.js (ESTE ES EL BLOQUE CORRECTO)
// --- RUTAS MEJORADAS PARA MODERACIÓN DE CONTENIDO ---
app.get('/admin/moderation', requireModerator, async (req, res, next) => {
    try {
        const firstPendingPost = await Post.findOne({ status: 'pending' }).sort({ createdAt: 'asc' });

        if (firstPendingPost) {
            res.redirect(`/admin/moderation/view/${firstPendingPost._id}`);
        } else {
            res.render('admin/moderation-view', { 
                post: null, 
                pendingCount: 0,
                layout: false
            });
        }
    } catch (err) {
        next(err);
    }
});

app.get('/admin/moderation/view/:id', requireModerator, async (req, res, next) => {
    try {
        const postToModerate = await Post.findById(req.params.id).populate('userId', 'username');
        if (!postToModerate || postToModerate.status !== 'pending') {
            return res.redirect('/admin/moderation');
        }
        
        const pendingCount = await Post.countDocuments({ status: 'pending' });

        res.render('admin/moderation-view', {
            post: postToModerate,
            pendingCount: pendingCount,
            layout: false
        });

    } catch (err) {
        next(err);
    }
});

app.post('/admin/post/:id/update-status', requireModerator, async (req, res, next) => {
    try {
        const { status } = req.body;
        const currentPostId = req.params.id;
        const validStatuses = ['approved', 'rejected'];
        if (!validStatuses.includes(status)) throw new Error('Estado no válido');

        const post = await Post.findById(currentPostId);
        if(!post) return res.redirect('/admin/moderation');

        if (status === 'approved') {
            post.status = status;
            await post.save();
            await new Notification({ userId: post.userId, type: 'admin', message: `Tu publicación "${post.description.slice(0, 20)}..." fue aprobada.` }).save();
        } else if (status === 'rejected') {
     // --- INICIO DEL CÓDIGO CORREGIDO ---
     for (const fileUrl of post.files) {
        const publicId = getPublicId(fileUrl);
        if (publicId) {
            // Determina si es un video o una imagen para la correcta eliminación
            const resourceType = fileUrl.includes('.mp4') || fileUrl.includes('.mov') ? 'video' : 'image';
            await cloudinary.uploader.destroy(publicId, { resource_type: resourceType }).catch(err => console.error("Fallo al eliminar de Cloudinary:", err));
        }
    }
    // --- FIN DEL CÓDIGO CORREGIDO ---
    await Post.findByIdAndDelete(currentPostId);
    await new Notification({ userId: post.userId, type: 'admin', message: `Tu publicación fue rechazada por no cumplir las normas.` }).save();
}
        
        const nextPost = await Post.findOne({ status: 'pending' }).sort({ createdAt: 'asc' });
        
        if (nextPost) {
            res.redirect(`/admin/moderation/view/${nextPost._id}`);
        } else {
            res.redirect('/admin/moderation');
        }

    } catch (err) {
        next(err);
    }
});
// =============================================
// RUTAS DE MONETIZACIÓN (COMPLETAS)
// =============================================
app.post('/post/:id/boost', requireAuth, isPostOwner, async (req, res, next) => {
    const { boost, boostLabel, boostColor } = req.body;
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const post = await Post.findById(req.params.id).session(session);
            const user = await User.findById(req.user._id).session(session);
            const [plan, cost] = boost.split('_');
            const boostCost = parseInt(cost, 10);
            const boostDays = { viral: 1, tendencia: 3, hot: 10 }[plan];
            if (user.tpysBalance < boostCost) throw new Error('No tienes suficientes TPYS.');
            user.tpysBalance -= boostCost;
            post.boostedUntil = new Date(Date.now() + boostDays * 24 * 60 * 60 * 1000);
            post.boostOptions = { color: boostColor, label: boostLabel };
            await new Transaction({ type: 'boost', buyerId: user._id, postId: post._id, amount: boostCost, netEarning: 0 }).save({ session });
            await user.save({ session });
            await post.save({ session });
        });
        res.json({ success: true, message: "¡Anuncio promocionado!", redirectUrl: `/anuncio/${req.params.id}` });
    } catch (err) { res.status(400).json({ success: false, message: err.message }); } finally { await dbSession.endSession(); }
});

app.post('/buy-video/:id', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const post = await Post.findById(req.params.id).session(session);
            if (!post || post.type !== 'video' || post.isSubscriberOnly) throw new Error('Video no disponible.');
            const buyer = await User.findById(req.user._id).session(session);
            if (buyer.tpysBalance < post.price) throw new Error('No tienes suficientes TPYS.');
            if (buyer.purchasedVideos.includes(post._id)) throw new Error('Ya has comprado este video.');
            const seller = await User.findById(post.userId).session(session);
            const price = post.price;
            const netEarning = price * res.locals.siteConfig.creatorEarningRate; 
            buyer.tpysBalance -= price;
            seller.tpysBalance += netEarning;
            buyer.purchasedVideos.push(post._id);
            post.salesCount += 1;
            await buyer.save({ session });
            await seller.save({ session });
            await post.save({ session });
            await new Transaction({ type: 'video_purchase', sellerId: seller._id, buyerId: buyer._id, postId: post._id, amount: price, netEarning }).save({ session });
            await new Notification({ userId: seller._id, actorId: buyer._id, type: 'sale', postId: post._id, message: `ha comprado tu video.` }).save({ session });
        });
        res.json({ success: true, message: "¡Compra exitosa!" });
    } catch (err) { res.status(400).json({ success: false, message: err.message }); } finally { await dbSession.endSession(); }
});

app.post('/user/:id/subscribe', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const creator = await User.findById(req.params.id).session(session);
            if (!creator || !creator.subscriptionSettings.isActive) throw new Error("Las suscripciones para este creador no están activas.");

            const buyer = await User.findById(req.user._id).session(session);
            const price = creator.subscriptionSettings.price;

            if (buyer._id.equals(creator._id)) throw new Error("No puedes suscribirte a ti mismo.");
            if (buyer.tpysBalance < price) throw new Error("No tienes suficientes TPYS para suscribirte.");

            const netEarning = price * res.locals.siteConfig.creatorEarningRate;
            buyer.tpysBalance -= price;
            creator.tpysBalance += netEarning;

            const now = new Date();
            const existingSubIndex = buyer.subscriptions.findIndex(s => s.creatorId.equals(creator._id));
            let newEndDate = new Date(new Date(now).setMonth(now.getMonth() + 1));

            if (existingSubIndex > -1) {
                const currentEndDate = new Date(buyer.subscriptions[existingSubIndex].endDate);
                if (currentEndDate > now) {
                    newEndDate = new Date(currentEndDate.setMonth(currentEndDate.getMonth() + 1));
                }
                buyer.subscriptions[existingSubIndex].endDate = newEndDate;
            } else {
                buyer.subscriptions.push({ creatorId: creator._id, endDate: newEndDate });
            }

            const subscriberIndex = creator.subscribers.findIndex(s => s.subscriberId.equals(buyer._id));
            if (subscriberIndex > -1) {
                creator.subscribers[subscriberIndex].endDate = newEndDate;
            } else {
                creator.subscribers.push({ subscriberId: buyer._id, endDate: newEndDate });
            }
            
            // Lógica de conversación y mensaje automático
            let conversation = await Conversation.findOne({ participants: { $all: [buyer._id, creator._id] } }).session(session);
            if (!conversation) {
                conversation = new Conversation({ participants: [buyer._id, creator._id] });
                await conversation.save({ session });
            }

            if (creator.automatedMessageEnabled && creator.automatedChatMessage) {
                const autoMessage = new Message({
                    conversationId: conversation._id,
                    senderId: creator._id,
                    text: creator.automatedChatMessage
                });
                await autoMessage.save({ session });
                conversation.lastMessage = autoMessage._id;
                await conversation.save({ session });
                await new Notification({
                    userId: buyer._id,
                    actorId: creator._id,
                    type: 'message',
                    message: `Te ha enviado un mensaje.`
                }).save({ session });
            }


            await new Transaction({ type: 'subscription', sellerId: creator._id, buyerId: buyer._id, amount: price, netEarning }).save({ session });
            await new Notification({ userId: creator._id, actorId: buyer._id, type: 'subscribe', message: `se ha suscrito a tu perfil.` }).save({ session });

            buyer.markModified('subscriptions');
            creator.markModified('subscribers');



            await buyer.save({ session });
            await creator.save({ session });
        });

        res.json({ success: true, message: '¡Suscripción exitosa!' });
    } catch (err) {
        res.status(400).json({ success: false, message: err.message });
    } finally {
        await dbSession.endSession();
    }
});

app.get('/add-funds', requireAuth, (req, res) => res.render('add-funds'));
app.post('/pagopar/create-order', requireAuth, async (req, res) => {
    try {
        const { amountGs, tpysAmount } = req.body;
        const amount = parseInt(amountGs, 10);
        const orderId = `TPY-${req.user._id.toString().slice(-4)}-${Date.now()}`;
        const hash = crypto.createHash('md5').update(PAGOPAR_PRIVATE_TOKEN + orderId + amount).digest('hex');
        const orderData = {
            "token": hash, "comprador": { "ruc": "0", "email": req.user.email, "nombre": req.user.username, "telefono": "0999999999", "direccion": "N/A", "documento": "0", "razon_social": req.user.username, "tipo_documento": "CI" },
            "public_key": PAGOPAR_PUBLIC_TOKEN, "monto_total": amount, "tipo_pedido": "VENTA-COMERCIO",
            "id_pedido_comercio": orderId, "descripcion_resumen": `Compra de ${tpysAmount} TPYS`,
            "fecha_maxima_pago": new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10).replace(/-/g, ""),
            "url_retorno_ok": `${process.env.BASE_URL || 'http://localhost:3000'}/payment-success`,
            "url_retorno_error": `${process.env.BASE_URL || 'http://localhost:3000'}/payment-error`,
            "url_notificacion_pedido": `${process.env.BASE_URL || 'http://localhost:3000'}/pagopar/callback`
        };
        const response = await fetch('https://api.pagopar.com/api/pedido/generar/desarrollo', { method: 'POST', body: JSON.stringify(orderData), headers: { 'Content-Type': 'application/json' } });
        const jsonResponse = await response.json();
        if (jsonResponse.respuesta === true) {
            await new Transaction({ type: 'tpys_purchase', buyerId: req.user._id, amount, netEarning: parseInt(tpysAmount, 10), currency: 'PYG', paymentGatewayId: orderId, status: 'PENDIENTE' }).save();
            res.json({ success: true, paymentUrl: jsonResponse.resultado[0].data });
        } else { throw new Error(jsonResponse.resultado || 'Error con Pagopar'); }
    } catch (err) { res.status(500).json({ success: false, message: 'Error al crear la orden de pago.' }); }
});

app.post('/pagopar/callback', async (req, res) => {
    const { hash, id_pedido_comercio, estado } = req.body;
    const localHash = crypto.createHash('sha1').update(PAGOPAR_PRIVATE_TOKEN + id_pedido_comercio + estado).digest('hex');
    if (hash !== localHash) return res.status(403).send("Hash inválido.");
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const transaction = await Transaction.findOne({ paymentGatewayId: id_pedido_comercio, status: 'PENDIENTE' }).session(session);
            if (transaction) {
                if (estado === 'pagado') {
                    const user = await User.findById(transaction.buyerId).session(session);
                    user.tpysBalance += transaction.netEarning;
                    transaction.status = 'COMPLETADO';
                    await user.save({ session });
                    await transaction.save({ session });
                } else if (estado === 'cancelado') {
                    transaction.status = 'CANCELADO';
                    await transaction.save({ session });
                }
            }
        });
        res.status(200).send("OK");
    } catch (err) { res.status(500).send("Error al procesar el pago."); } finally { await dbSession.endSession(); }
});

app.get('/payment-success', (req, res) => res.render('payment-status', { success: true, message: '¡Pago exitoso! Tu saldo ha sido actualizado.' }));
app.get('/payment-error', (req, res) => res.render('payment-status', { success: false, message: 'El pago ha fallado o ha sido cancelado.' }));

// =============================================
// RUTAS DE CHAT (COMPLETAS)
// =============================================
// Archivo: tpy.com/server.js

app.get('/chat', requireAuth, async (req, res, next) => {
    try {
        const conversations = await Conversation.find({ participants: req.user._id })
            .populate('participants', 'username profilePic')
            .populate({ path: 'lastMessage', select: 'text createdAt' })
            // --- LÍNEA MODIFICADA ---
            // Ordenamos por la fecha de actualización de la conversación, de la más reciente a la más antigua.
            .sort({ updatedAt: -1 }); 
            // --- FIN DE LA MODIFICACIÓN ---
            
        res.render('chat-list', { conversations });
    } catch (err) { 
        next(err); 
    }
});

app.get('/chat/with/:userId', requireAuth, async (req, res, next) => {
    const { userId } = req.params;
    if (req.user._id.equals(userId)) return res.redirect('/chat');
    try {
        let conversation = await Conversation.findOne({ participants: { $all: [req.user._id, userId] } });
        if (!conversation) {
            const creator = await User.findById(userId);
            const isSubscribed = req.user.subscriptions.some(s => s.creatorId.equals(creator._id) && new Date(s.endDate) > new Date());
            if (!isSubscribed && !creator.followers.includes(req.user._id)) { // Permite iniciar chat si lo sigues
                return res.status(403).render('error', { message: 'Debes suscribirte o seguir a este usuario para chatear.' });
            }
            conversation = new Conversation({ participants: [req.user._id, userId] });
            await conversation.save();
        }
        res.redirect(`/chat/${conversation._id}`);
    } catch (err) { next(err); }
});

app.get('/chat/:conversationId', requireAuth, async (req, res, next) => {
    try {
        const conversation = await Conversation.findById(req.params.conversationId).populate('participants', 'username profilePic');
        if (!conversation || !conversation.participants.some(p => p._id.equals(req.user._id))) return res.status(403).render('error', { message: 'No tienes acceso a este chat.' });
        const messages = await Message.find({ conversationId: conversation._id }).populate('senderId', 'username profilePic').sort('createdAt');
        const otherUser = conversation.participants.find(p => !p._id.equals(req.user._id));
        await Message.updateMany({ conversationId: conversation._id, senderId: otherUser._id, isRead: false }, { $set: { isRead: true } });
        res.render('chat-detail', { conversation, messages, otherUser });
    } catch (err) { next(err); }
});

// tpy.com/server.js

// Archivo: tpy.com/server.js

app.post('/chat/:conversationId/messages', requireAuth, upload.single('chatMedia'), async (req, res, next) => {
    const { text, tpysAmount } = req.body;
    const amount = Number(tpysAmount) || 0;
    const dbSession = await mongoose.startSession();

    try {
        // Validación para no permitir mensajes totalmente vacíos (sin texto Y sin archivo)
        if (!text && !req.file) {
            return res.status(400).json({ success: false, message: 'El mensaje no puede estar vacío.' });
        }

        let populatedMessage;
        await dbSession.withTransaction(async (session) => {
            const CREATOR_EARNING_RATE = res.locals.siteConfig.creatorEarningRate;
            const conversation = await Conversation.findById(req.params.conversationId).session(session);
            if (!conversation.participants.includes(req.user._id)) {
                throw new Error("No eres parte de esta conversación.");
            }
            
            const sender = await User.findById(req.user._id).session(session);
            const receiverId = conversation.participants.find(p => !p.equals(sender._id));
            const receiver = await User.findById(receiverId).session(session);

            // Lógica para manejar las propinas (tips)
            if (amount > 0) {
                if (sender.tpysBalance < amount) throw new Error("No tienes suficientes TPYS.");
                const netEarning = amount * CREATOR_EARNING_RATE;
                sender.tpysBalance -= amount;
                receiver.tpysBalance += netEarning;
                await new Transaction({ type: 'chat_tip', sellerId: receiver._id, buyerId: sender._id, amount, netEarning }).save({ session });
                await new Notification({ userId: receiver._id, actorId: sender._id, type: 'tip', message: `te envió ${amount} TPYS en el chat.` }).save({ session });
            }

            // Construcción del objeto del nuevo mensaje
            const newMessageData = {
                conversationId: conversation._id,
                senderId: sender._id,
                text: text, // Se guarda el texto que llegue
                tpysAmount: amount
            };

            // Si se subió un archivo, se añaden sus datos al objeto
            if (req.file) {
                newMessageData.mediaUrl = req.file.path;
                newMessageData.mediaType = req.file.mimetype.startsWith('image') ? 'image' : 'video';
            }

            // Creación y guardado del nuevo mensaje en la base de datos
            const newMessage = new Message(newMessageData);
            await newMessage.save({ session });
            
            // Actualización de la conversación con el último mensaje
            conversation.lastMessage = newMessage._id;
            
            // Guardado de los cambios en los usuarios y la conversación
            await sender.save({ session });
            if (amount > 0) await receiver.save({ session });
            await conversation.save({ session });
            
            // Se "popula" el mensaje para devolverlo completo al frontend
            populatedMessage = await newMessage.populate('senderId', 'username profilePic');
        });
        
        // Se envía la respuesta exitosa con el mensaje creado
        res.json({ success: true, message: populatedMessage });

    } catch (err) {
        // En caso de error, se elimina el archivo subido a Cloudinary si existe
        if (req.file) {
            const publicId = getPublicId(req.file.path);
            if (publicId) await cloudinary.uploader.destroy(publicId, { resource_type: req.file.mimetype.startsWith('video') ? 'video' : 'image' });
        }
        res.status(400).json({ success: false, message: err.message });
    } finally {
        // Se finaliza la sesión de la base de datos
        await dbSession.endSession();
    }
});


// tpy.com/server.js

// --- INICIO DE CÓDIGO AÑADIDO ---
// RUTA PARA OBTENER MENSAJES NUEVOS (POLLING)
app.get('/chat/:conversationId/messages/since/:lastMessageId', requireAuth, async (req, res, next) => {
    try {
        const { conversationId, lastMessageId } = req.params;

        // Validamos que el usuario pertenezca a la conversación
        const conversation = await Conversation.findById(conversationId);
        if (!conversation || !conversation.participants.some(p => p._id.equals(req.user._id))) {
            return res.status(403).json({ success: false, message: 'Acceso denegado.' });
        }
        
        // Si no hay lastMessageId, no hay nada nuevo que buscar todavía
        if (lastMessageId === 'null') {
            return res.json({ success: true, messages: [] });
        }

        // Buscamos mensajes que sean más recientes que el último que tiene el cliente
        const newMessages = await Message.find({
            conversationId: conversationId,
            _id: { $gt: lastMessageId } // La clave: busca IDs mayores al último recibido
        })
        .populate('senderId', 'username profilePic')
        .sort({ createdAt: 'asc' });

        res.json({ success: true, messages: newMessages });

    } catch (err) {
        next(err);
    }
});
// --- FIN DE CÓDIGO AÑADIDO ---
// =============================================
//               FIN DE LA PARTE 2
// =============================================




// =============================================
//               SERVER.JS - PARTE 3 DE 3 (FINAL)
// =============================================

// RUTAS DEL PANEL DE CONFIGURACIÓN DEL CREADOR
// =============================================
app.get('/settings/:page', requireAuth, async (req, res, next) => {
    try {
        app.set('layout', 'settings/layout'); // Usar el layout del panel de configuración
        const { page } = req.params;
        const validPages = ['dashboard', 'profile', 'subscriptions', 'automations', 'payouts'];
        if (!validPages.includes(page)) return res.redirect('/settings/dashboard');

        let data = { page };

        if (page === 'dashboard') {
            const transactions = await Transaction.find({ sellerId: req.user._id }).populate('buyerId', 'username').sort({ createdAt: -1 });
            const totalNetEarnings = transactions.reduce((sum, t) => sum + (t.netEarning || 0), 0);
            const activeSubscribers = req.user.subscribers.filter(s => new Date(s.endDate) > new Date()).length;
            data = { ...data, totalNetEarnings, transactions, activeSubscribersCount: activeSubscribers };
        }
        if (page === 'payouts') {
            data.withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ createdAt: -1 });
        }
        res.render(`settings/${page}`, data);
    } catch(err) { next(err); }
});

app.post('/settings/profile', requireAuth, upload.single('profilePic'), async (req, res, next) => {
    try {
        const { username, bio, location, whatsapp, gender, orientation } = req.body;
        const userToUpdate = await User.findById(req.user._id);
        
        if (req.file && userToUpdate.profilePic && !userToUpdate.profilePic.includes('default.png')) {
            const publicId = getPublicId(userToUpdate.profilePic);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }
        const updateData = { username, bio, location, whatsapp, gender, orientation };
        if (req.file) updateData.profilePic = req.file.path;
        await User.findByIdAndUpdate(req.user._id, updateData);
        res.redirect('/settings/profile');
    } catch (err) { next(err); }
});

app.post('/settings/subscriptions', requireAuth, async (req, res) => {
    const { isActive, price } = req.body;
    req.user.subscriptionSettings.isActive = isActive === 'on';
    if (price) req.user.subscriptionSettings.price = Number(price);
    await req.user.save();
    res.redirect('/settings/subscriptions');
});

app.post('/settings/automations', requireAuth, async (req, res) => {
    const { automatedMessageEnabled, automatedChatMessage } = req.body;
    req.user.automatedMessageEnabled = automatedMessageEnabled === 'on';
    req.user.automatedChatMessage = automatedChatMessage;
    await req.user.save();
    res.redirect('/settings/automations');
});

app.post('/settings/payouts', requireAuth, async (req, res, next) => {
    try {
        const { amount, method, fullName, ci, bankName, accountNumber, phone, alias } = req.body;
        const user = req.user;
        const amountNum = parseInt(amount);
        if (isNaN(amountNum) || amountNum < 30000) throw new Error(`El monto mínimo es de 30.000 Gs.`);
        const tpysToWithdraw = Math.floor(amountNum / 100);
        if (user.tpysBalance < tpysToWithdraw) throw new Error("No tienes suficientes TPYS para retirar ese monto.");
        
        let details = {};
        if (method === 'transferencia') details = { fullName, ci, bankName, accountNumber, alias };
        else if (method === 'giro') details = { fullName, ci, phone };
        else throw new Error("Método de retiro no válido.");
        
        await User.findByIdAndUpdate(user._id, { $inc: { tpysBalance: -tpysToWithdraw } });
        await new Withdrawal({ userId: user._id, amount: amountNum, method, details, status: 'Pendiente' }).save();
        
        res.redirect('/settings/payouts');
    } catch(err) { next(err); }
});


// =============================================
// RUTAS DE ADMINISTRADOR (NUEVAS Y MEJORADAS)
// =============================================
app.get('/admin', requireAdmin, (req, res) => res.redirect('/admin/dashboard'));

app.get('/admin/dashboard', requireAdmin, async (req, res, next) => {
    try {
        const [totalUsers, totalPosts, pendingWithdrawals] = await Promise.all([
            User.countDocuments(),
            Post.countDocuments(),
            Withdrawal.countDocuments({ status: 'Pendiente' })
        ]);
        const stats = { totalUsers, totalPosts, pendingWithdrawals };
        res.render('admin/dashboard.html', { stats: stats, path: req.path });
    } catch (err) { next(err); }
});

// --- GESTIÓN DE USUARIOS ---
app.get('/admin/users', requireAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 15;
        let query = {};
        if (req.query.search) {
            const regex = { $regex: req.query.search, $options: 'i' };
            query = { $or: [{ username: regex }, { email: regex }] };
        }
        const totalUsers = await User.countDocuments(query);
        const totalPages = Math.ceil(totalUsers / itemsPerPage);
        const users = await User.find(query).sort({ createdAt: -1 }).skip((page - 1) * itemsPerPage).limit(itemsPerPage);
        res.render('admin/users.html', { users: users, totalPages: totalPages, currentPage: page, path: req.path, query: req.query });
    } catch (err) { next(err); }
});

// ======================================================
// RUTA DE DETALLE DE USUARIO DEL ADMIN (VERSIÓN MEJORADA)
// ======================================================
app.get('/admin/user/:id', requireAdmin, async (req, res, next) => {
    try {
        const userId = req.params.id;
        const user = await User.findById(userId)
            .populate('followers', 'username profilePic')
            .populate('following', 'username profilePic')
            .populate({
                path: 'subscriptions.creatorId',
                select: 'username profilePic'
            })
            .populate('subscribers.subscriberId', 'username profilePic');

        if (!user) {
            return res.redirect('/admin/users');
        }

        const [posts, transactions, withdrawals] = await Promise.all([
            Post.find({ userId: userId }).sort({ createdAt: -1 }),
            Transaction.find({ $or: [{ buyerId: userId }, { sellerId: userId }] })
                .populate('buyerId', 'username')
                .populate('sellerId', 'username')
                .populate('postId', 'description')
                .sort({ createdAt: -1 }).limit(50),
            Withdrawal.find({ userId: userId }).sort({ createdAt: -1 })
        ]);
        const verification = await Verification.findOne({ userId: userId });

        // La ruta ahora renderiza el layout principal y le pasa 'admin/user-detail' como el cuerpo
        res.render('admin/user-detail.html', {
            
            user: user,
            posts: posts,
            transactions: transactions,
            withdrawals: withdrawals,
            verification: verification, // <-- Pasa el documento a la vista
            path: req.path
        });

    } catch (err) {
        next(err);
    }
});

app.post('/admin/user/:id/toggle-ban', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (user && !user.isAdmin) { // Previene que el admin se banee a sí mismo
            user.isBanned = !user.isBanned;
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});

app.post('/admin/user/:id/toggle-verify', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (user) {
            user.isVerified = !user.isVerified;
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});

app.post('/admin/user/:id/adjust-balance', requireAdmin, async (req, res, next) => {
    try {
        const { amount, reason } = req.body;
        const amountNum = parseInt(amount);
        if (isNaN(amountNum)) return res.redirect(`/admin/user/${req.params.id}`);
        const user = await User.findById(req.params.id);
        if (user) {
            user.tpysBalance += amountNum;
            await new Transaction({ type: 'admin_adjustment', buyerId: user._id, adminId: req.user._id, amount: amountNum, description: reason }).save();
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});




// =============================================
// RUTA PARA EL PANEL DE ANALÍTICAS
// =============================================
// En tentacionpy/server.js, reemplaza la ruta de analytics existente

app.get('/admin/analytics', requireAdmin, async (req, res, next) => {
    try {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const TASA_CONVERSION_GS = 100; // 1 TPYS = 100 Gs.

        // 1. Ganancias diarias (Mejorado con Guaraníes)
        const dailyPlatformEarnings = await Transaction.aggregate([
            { $match: { createdAt: { $gte: thirtyDaysAgo }, type: { $in: ['video_purchase', 'subscription', 'donation', 'chat_tip'] } } },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    totalAmount: { $sum: "$amount" },
                    totalNetEarning: { $sum: "$netEarning" }
                }
            },
            {
                $project: {
                    date: "$_id",
                    commissionTPYS: { $subtract: ["$totalAmount", "$totalNetEarning"] },
                    commissionGS: { $multiply: [{ $subtract: ["$totalAmount", "$totalNetEarning"] }, TASA_CONVERSION_GS] }
                }
            },
            { $sort: { date: 1 } }
        ]);

        // 2. Top 5 creadores con más ganancias (código existente sin cambios)
        const topCreators = await Transaction.aggregate([
            { $match: { sellerId: { $ne: null } } },
            {
                $group: {
                    _id: "$sellerId",
                    totalEarnings: { $sum: "$netEarning" }
                }
            },
            { $sort: { totalEarnings: -1 } },
            { $limit: 5 },
            {
                $lookup: {
                    from: 'users',
                    localField: '_id',
                    foreignField: '_id',
                    as: 'creatorInfo'
                }
            },
            { $unwind: "$creatorInfo" }
        ]);

        // 3. Tipos de transacciones más comunes (código existente sin cambios)
        const transactionTypes = await Transaction.aggregate([
            { $group: { _id: "$type", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        // 4. NUEVO: Métricas Clave
        const totalRevenueTPYS = await Transaction.aggregate([ { $match: { type: { $in: ['video_purchase', 'subscription', 'donation', 'chat_tip'] } } }, { $group: { _id: null, total: { $sum: "$amount" } } } ]);
        const totalCommissionTPYS = await Transaction.aggregate([ { $match: { type: { $in: ['video_purchase', 'subscription', 'donation', 'chat_tip'] } } }, { $group: { _id: null, total: { $sum: { $subtract: ["$amount", "$netEarning"] } } } } ]);
        const newUsersLast30Days = await User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });

        const keyMetrics = {
            totalRevenueTPYS: totalRevenueTPYS.length > 0 ? totalRevenueTPYS[0].total : 0,
            totalCommissionTPYS: totalCommissionTPYS.length > 0 ? totalCommissionTPYS[0].total : 0,
            newUsersLast30Days: newUsersLast30Days
        };

        res.render('admin/analytics.html', {
            path: req.path,
            TASA_CONVERSION_GS, // Pasamos la tasa para usarla en el frontend
            analytics: {
                dailyPlatformEarnings,
                topCreators,
                transactionTypes,
                keyMetrics // Nuevos datos
            }
        });

    } catch (err) {
        next(err);
    }
});



// --- GESTIÓN DE CONTENIDO ---
app.get('/admin/posts', requireAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 15;
        let query = {};
        if (req.query.search) {
            query.description = { $regex: req.query.search, $options: 'i' };
        }
        const totalPosts = await Post.countDocuments(query);
        const totalPages = Math.ceil(totalPosts / itemsPerPage);
        const posts = await Post.find(query).populate('userId', 'username').sort({ createdAt: -1 }).skip((page - 1) * itemsPerPage).limit(itemsPerPage);
        res.render('admin/posts.html', { posts: posts, totalPages: totalPages, currentPage: page, path: req.path, query: req.query });
    } catch (err) { next(err); }
});

// --- GESTIÓN DE RETIROS (EXISTENTE) ---
app.get('/admin/withdrawals', requireAdmin, async (req, res, next) => {
    try {
        const withdrawals = await Withdrawal.find().populate('userId', 'username email').sort({ createdAt: -1 });
        res.render('admin/withdrawals.html', { withdrawals: withdrawals, path: req.path });
    } catch (err) { next(err); }
});

app.post('/admin/withdrawal/:id/update', requireAdmin, async (req, res, next) => {
    try {
        const { status } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal) return res.status(404).send('Solicitud no encontrada');
        if (withdrawal.status === 'Pendiente' && status === 'Rechazado') {
            const tpysToReturn = Math.floor(withdrawal.amount / 100);
            await User.findByIdAndUpdate(withdrawal.userId, { $inc: { tpysBalance: tpysToReturn } });
        }
        withdrawal.status = status;
        await withdrawal.save();
        res.redirect('/admin/withdrawals');
    } catch (err) { next(err); }
});


// To: tpy.com/server.js

// --- RUTAS DE VERIFICACIÓN DE IDENTIDAD ---
app.get('/verify-account', requireAuth, async (req, res, next) => {
    try {
        if (req.user.isVerified) {
            return res.redirect('/new-post'); // Si ya está verificado, que no vea esta página
        }
        const existingVerification = await Verification.findOne({ userId: req.user._id });
        res.render('verify-account', { 
            status: existingVerification ? existingVerification.status : 'unsubmitted',
            reason: existingVerification ? existingVerification.rejectionReason : null
        });
    } catch (err) { next(err); }
});

app.post('/verify-account', requireAuth, upload.array('verificationPhotos', 2), async (req, res, next) => {
    try {
        if (req.user.isVerified) return res.redirect('/feed');
        if (!req.files || req.files.length !== 2) throw new Error("Debes subir exactamente dos imágenes.");

        // Eliminar solicitud rechazada anterior si existe
        await Verification.findOneAndDelete({ userId: req.user._id });

        const newVerification = new Verification({
            userId: req.user._id,
            idPhoto: req.files[0].path,
            selfiePhoto: req.files[1].path,
            status: 'pending'
        });
        await newVerification.save();
        res.redirect('/verify-account');
    } catch (err) { next(err); }
});


// To: tpy.com/server.js

// --- RUTAS DE ADMIN PARA VERIFICACIONES ---
app.get('/admin/verifications', requireModerator, async (req, res, next) => {
    try {
        const pendingVerifications = await Verification.find({ status: 'pending' }).populate('userId', 'username');
        res.render('admin/verifications.html', { verifications: pendingVerifications, path: req.path });
    } catch (err) { next(err); }
});

// En server.js
app.post('/admin/verification/:id/approve', requireModerator, async (req, res, next) => {
    try {
        const verification = await Verification.findById(req.params.id);
        if (!verification) throw new Error('Solicitud no encontrada.');

        // Actualizamos al usuario como verificado
        await User.findByIdAndUpdate(verification.userId, { isVerified: true });
        
        // ¡IMPORTANTE! Comentamos o eliminamos las líneas que borran los archivos.
        // await cloudinary.uploader.destroy(getPublicId(verification.idPhoto));
        // await cloudinary.uploader.destroy(getPublicId(verification.selfiePhoto));

        // En lugar de borrar el registro, actualizamos su estado a "aprobado"
        verification.status = 'approved';
        await verification.save();

        await new Notification({ userId: verification.userId, type: 'admin', message: '¡Felicidades! Tu cuenta ha sido verificada.' }).save();
        res.redirect('/admin/verifications');
    } catch (err) { next(err); }
});

// En server.js
app.post('/admin/verification/:id/reject', requireModerator, async (req, res, next) => {
    try {
        const { reason } = req.body;
        const verification = await Verification.findById(req.params.id);
        
        if (verification) {
            // Actualizamos el estado y el motivo del rechazo
            verification.status = 'rejected';
            verification.rejectionReason = reason || 'Los documentos no cumplían con los requisitos.';
            await verification.save();

            // Desmarcamos al usuario como verificado (si es que lo estaba por error)
            await User.findByIdAndUpdate(verification.userId, { isVerified: false });
            
            // ¡IMPORTANTE! También comentamos las líneas de borrado aquí.
            // await cloudinary.uploader.destroy(getPublicId(verification.idPhoto));
            // await cloudinary.uploader.destroy(getPublicId(verification.selfiePhoto));
            
            await new Notification({ userId: verification.userId, type: 'admin', message: `Tu solicitud de verificación fue rechazada. Motivo: ${reason || 'No especificado'}` }).save();
        }

        res.redirect('/admin/verifications');
    } catch (err) { next(err); }
});
// =============================================
// MANEJADORES DE ERRORES Y ARRANQUE DEL SERVIDOR
// =============================================
app.use((req, res, next) => { res.status(404).render('error', { message: 'Página no encontrada (404)', layout: false }); });

app.use((err, req, res, next) => {
  console.error("❌ ERROR CAPTURADO:", err);
  const status = err.status || 500;
  const message = err.message || 'Ocurrió un error inesperado en el servidor.';
  res.status(status).render('error', { message, layout: false });
});

app.listen(PORT, () => console.log(`🚀 Servidor TentacionPY corriendo en http://localhost:${PORT}`));


// =============================================
//               FIN DEL ARCHIVO
// =============================================
