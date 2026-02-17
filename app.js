const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cookieParser = require("cookie-parser");

const globalErrorHandler = require("./controllers/errorControllers");
const foreclosureDataRouter = require("./routes/foreclosureData.route");
const userRouter = require("./routes/user.routes");
const AppError = require("./utils/appError");

const app = express();

// GLOBAL MIDDLEWARES
// set security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}
// Limit request from same API
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: `Too many request from this IP, please try again in an hour!`,
});
app.use("/api", limiter);

app.use(
  cors({
    origin: [
      "http://127.0.0.1:5500",
      "http://localhost:5500",
      "https://eskeadmast.github.io",
    ],
    credentials: true,
  }),
);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: "10kb" }));

// cookie prser
app.use(cookieParser());

// Data sanitization against NoSQL query injections
app.use((req, res, next) => {
  req.query = { ...req.query };
  mongoSanitize()(req, res, next);
});
// app.use((req, res, next) => {
//   const sanitize = obj => {
//     for (let key in obj) {
//       if (key.startsWith('$') || key.includes('.')) {
//         delete obj[key];
//       }
//     }
//     return obj;
//   };
//   req.body = sanitize(req.body);
//   req.params = sanitize(req.params);
//   req.query = sanitize({ ...req.query }); // clone to avoid immutability issues
//   next();
// });

// data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(
  hpp({
    whitelist: [],
  }),
);

// serving static files
// app.use(express.static());
app.get("/", (req, res) => {
  res.status(200).json({ message: "Backend is running!" });
});

app.use("/api/v1/foreclosures", foreclosureDataRouter);
app.use("/api/v1/users", userRouter);

app.use((req, res, next) => {
  next(new AppError(`Cannot find ${req.originalUrl} on this server`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
