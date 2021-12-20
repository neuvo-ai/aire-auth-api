import express from "express";
import { body, validationResult, matchedData } from "express-validator";
// TODO: Import models from schemata
import { sign, jwtValidation } from "../sign";
import logger from "../logger";
import _ from "lodash";
import { Admin } from "../models/admin";
import { AuditLog } from "../models/audit";
import expressJwt from "express-jwt";
export interface JWTRequest extends express.Request {
	user: any;
}
const router = express.Router();

const config = require(`${(process.env.CONFIG_PATH || "../../config/")}config.${(process.env.NODE_ENV || "development")}.json`);

const issuer = config.server.jwt.issuer;
const issuerRefresh = config.server.jwt.issuerRefresh; 

router.post("/login", [
	body("email", "Invalid email format").isEmail(),
	body("password", "Invalid password format").isByteLength({
		min: 1,
		max: 10240
	})
], async (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const bodyValues = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		const admin = await Admin.findOne({ email: bodyValues.email });
		if (await admin.verifyPassword(bodyValues.password) === true) {
			// Accept login only if admin has permissions
			if (admin.permissions.length > 0) {
				const jwt = sign(
					{
						_id: admin._id,
						email: admin.email,
						permissions: admin.permissions
					},
					issuer,
					"1h"
				);
				const refreshToken = sign(
					{
						_id: admin._id,
						email: admin.email,
						permissions: admin.permissions
					},
					issuerRefresh,
					"7d"
				);
				void AuditLog({
					type: "login-success",
					adminId: admin._id,
					target: "self",
				}, req);
				return res.status(200).json({ success: true, jwt, refreshToken, email: admin.email });
			} else {
				void AuditLog({
					type: "login-fail",
					adminId: admin._id,
					target: "self",
					details: "No permissions"
				}, req);
				return res.status(403).json({ error: "AdminNoPermissions" });
			}
		} else {
			void AuditLog({
				type: "login-fail",
				adminId: admin._id,
				target: "self",
			}, req);
			return res.status(403).json({ error: "AdminWrongPassword" });
		}
	} catch (e) {
		logger.error(e.message);
		void AuditLog({
			type: "login-not-found",
			target: "self",
			details: bodyValues.email
		}, req);
		return res.status(404).json({ error: "AdminNotFound" });
	}
});

router.post("/refresh", expressJwt(jwtValidation(issuerRefresh)), async (req: JWTRequest, res: express.Response) => {
	try {
		const admin = await Admin.findById(req.user._id);
		// If a password change or reset has been issued, we want to deny token refresh, this will effectively kick them back to the login page.
		// The goal is to deny all active tokens for an admin if their account has been compromised.
		if (Math.floor(Date.parse(admin.pwdChangedAt)) / 1000 < req.user.iat) {
			const jwt = sign(
				{
					_id: admin._id,
					email: admin.email,
					permissions: admin.permissions
				},
				issuer,
				"1h"
			);
			void AuditLog({
				type: "login-refresh",
				adminId: admin._id,
				target: "self",
			}, req);
			return res.status(200).json({ success: true, jwt, email: admin.email });
		} else {
			void AuditLog({
				type: "login-refresh-denied",
				adminId: admin._id,
				target: "self",
			}, req);
			return res.status(403).json({ error: "JWTForbidden" });
		}
	} catch (e) {
		logger.error(e.message);
		void AuditLog({
			type: "login-refresh-fail",
			target: "self",
			details: JSON.stringify(req.user)
		}, req);
		return res.status(404).json({ error: "AdminNotFound" });
	}
});

router.post("/password", [
	body("email", "Invalid email format").isEmail(),
	body("oldPassword", "Invalid password format").isByteLength({
		min: 1,
		max: 10240
	}),
	body("newPassword", "Invalid password format").isByteLength({
		min: 1,
		max: 10240
	})
], async (req: express.Request, res: express.Response) => {
	const errors = validationResult(req);
	const bodyValues = matchedData(req);

	if (!errors.isEmpty()) {
		return res.status(400).json({
			error: "ValidatingError",
			message: "Validating parameters failed",
			errors: _.uniqWith(errors.array(), _.isEqual)
		});
	}

	try {
		const admin = await Admin.findOne({ email: bodyValues.email });
		if (await admin.verifyPassword(bodyValues.oldPassword) === true) {
			logger.silly("All good, changing password now");
			admin.password = bodyValues.newPassword;
			void AuditLog({
				type: "password-changed",
				adminId: admin._id,
				target: "self",
			}, req);
			await admin.save();
			return res.status(200).json({ success: true });
		} else {
			logger.verbose("Wrong password when trying to change");
			return res.status(404).json({ error: "PasswordChangeFailed" });
		}
	} catch (e) {
		logger.error(e.message);
		return res.status(404).json({ error: "AdminNotFound" });
	}
});

export default router;
