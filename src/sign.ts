import jwt from "jsonwebtoken";
import fs from "fs";
import { Request } from "express";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const config = require(`${(process.env.CONFIG_PATH || "../config/")}config.${(process.env.NODE_ENV || "development")}.json`);

const jwtPrivKey = fs.readFileSync(config.keyLocation.private, "utf8");
const jwtPubKey = fs.readFileSync(config.keyLocation.public, "utf8");

const issuerConfig = config.server.jwt.issuer;

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
const sign = (payload: any, issuer = issuerConfig, expiresIn = "30d"): string => {
	return jwt.sign(
		payload,
		jwtPrivKey,
		{
			algorithm: "RS512",
			expiresIn,
			issuer
		}
	);
};

const jwtValidation = (issuer = issuerConfig): any => {
	return {
		secret: jwtPubKey,
		issuer,
		algorithms: ["RS512"],
		// We override the existing authorization header parser so that we can pass the original JWT (coming from the client) to the req
		getToken: (req: Request) => {
			let originalJwt;
			if (req.headers.authorization && req.headers.authorization.split(" ")[0] === "Bearer") {
				originalJwt = req.headers.authorization.split(" ")[1];
				return originalJwt;
			} else if (req.query && req.query.token) {
				originalJwt = req.query.token;
				return originalJwt;
			}
			return undefined;
		}
	};
};

export { sign, jwtPubKey, jwtValidation };