import express from "express";
import winston from "winston";
import accountsRouter from "./routes/account.routes.js"
import { promises as fs } from "fs";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import { swaggerDocument } from "./doc.js"
import basicAuth from "express-basic-auth"

const { readFile, writeFile } = fs;

global.fileName = "accounts.json";

const { combine, timestamp, label, printf } = winston.format;
const myFormat = printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${label}] ${level}: ${message}`;
});
global.logger = winston.createLogger({
    level: "silly",
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: "my-bank-api.log" })
    ],
    format: combine(
        label({ label: "my-bank-api" }),
        timestamp(),
        myFormat
    )
});

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));
app.use("/doc", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

function getRole(username) {

	// Obs: O perfil de usuário está "hard coded", apenas para facilitar 
	// o entendimento. O ideal nesse ponto é buscar as informações do usuário 
	// de um banco de dados, servidor de autorização, etc.
    if (username == 'admin') {
        return 'admin'
    } else if (username == 'angelo') {
        return 'role1'
    }
}

function authorize(...allowed) {

    const isAllowed = role => allowed.indexOf(role) > -1;

    return (req, res, next) => {

        if (req.auth.user) {
            const role = getRole(req.auth.user);

            if (isAllowed(role)) {
                next()
            } else {
                res.status(401).send('Role not allowed');
            }
        } else {
            res.status(403).send('User not found');
        }
    }
}

app.use(basicAuth({
    authorizer: (username, password) => {

		// Obs: Usuário e senha estão "hard coded", apenas para facilitar 
		// o entendimento. O ideal nesse ponto é buscar as informações do usuário 
		// de um banco de dados, servidor de autorização, etc.
        const userMatches = basicAuth.safeCompare(username, 'admin');
        const pwdMatches = basicAuth.safeCompare(password, 'admin');

        const user2Matches = basicAuth.safeCompare(username, 'angelo');
        const pwd2Matches = basicAuth.safeCompare(password, '1234');

        return userMatches && pwdMatches || user2Matches && pwd2Matches;
    }
}))

app.use("/account", authorize('admin'), accountsRouter);

app.listen(3000, async () => {
    try {
        await readFile(global.fileName);
        logger.info("API Started!");
    } catch (err) {
        const initialJson = {
            nextId: 1,
            accounts: []
        }
        writeFile(global.fileName, JSON.stringify(initialJson)).then(() => {
            logger.info("API Started and File Created!");
        }).catch(err => {
            logger.error(err);
        });
    }
});