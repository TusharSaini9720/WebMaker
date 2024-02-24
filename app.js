const express = require("express");
const app = express();
const userRouter=require('./Router/userrouter');
const cors = require("cors");
const cookieParser = require('cookie-parser');

app.use(express.json());
const path = require("path");

app.use(express.static(path.join(__dirname, "/frontend/build")));

app.get("*", (req, res) =>
  res.sendFile(path.resolve(__dirname, "frontend", "build", "index.html"))
);
app.use(cors());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
  
    next();
  });
const corsOption = {
    origin: ['http://127.0.0.1:3001'],
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
}
app.use(cors(corsOption));
app.use(cookieParser());

app.use("/api/v1/users", userRouter);


module.exports =app;