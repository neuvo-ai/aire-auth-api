import mongoose from "mongoose";
import express from "express";

export interface AuditObjectInterface {
	type: string;
	entityId?: string;
	adminId?: string;
	target: string;
	targetId?: string;
	details?: string;
	ip?: string;
}

export interface AuditInterface extends AuditObjectInterface, mongoose.Document {
	createdAt?: Date;
}

const AuditSchema: any = new mongoose.Schema({
	createdAt: {
		type: Date,
		default: Date.now,
		index: true,
		required: true
	},
	type: {
		type: String,
		index: true,
		required: true
	},
	entityId: {
		type: mongoose.Schema.Types.ObjectId,
		index: true
	},
	adminId: {
		type: mongoose.Schema.Types.ObjectId,
		index: true
	},
	targetId: {
		type: mongoose.Schema.Types.ObjectId,
		index: true
	},
	target: {
		type: String,
		index: true
	},
	details: {
		type: String,
	},
	ip: {
		type: String
	}
});

const Audit: any = mongoose.model<AuditInterface>("Audit", AuditSchema);

const AuditLog = async (auditObject: AuditObjectInterface, req?: express.Request): Promise<void> => {
	if (typeof req === "object") {
		const ip = req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"] || req.connection.remoteAddress;
		auditObject.ip = ip.toString();
	}
	const audit = new Audit(auditObject);
	await audit.save();
};

export { Audit, AuditLog };