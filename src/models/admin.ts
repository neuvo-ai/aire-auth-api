/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/ban-types */
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import logger from "../logger";

export interface AdminInterface extends mongoose.Document {
	entityId: string;
	email: string;
	password: string;
	permissions: string[];
}

const AdminSchema: any = new mongoose.Schema({
	createdAt: {
		type: Date,
		default: Date.now,
		index: true
	},
	updatedAt: {
		type: Date,
		default: Date.now,
		index: true
	},
	email: {
		type: String,
		required: true,
		index: {
			unique: true
		},
		maxlength: 254
	},
	password: {
		type: String,
		required: true,
	},
	pwdChangedAt: {
		type: Date,
		default: Date.now(),
		index: true
	},
	permissions: [String]
});

let SALT_WORK_FACTOR = 15;

if (process.env.NODE_ENV === "test") {
	SALT_WORK_FACTOR = 4;
}

AdminSchema.pre("save", function(next: Function) {
	// Update updatedAt timestamp
	this.updatedAt = Date.now();
	// only hash the password if it has been modified (or is new)
	if (!this.isModified("password") || this.password === false) {
		return next();
	}
	void bcrypt.genSalt(SALT_WORK_FACTOR, (saltErr, salt) => {
		if (saltErr) {
			logger.error(saltErr);
			return next(saltErr);
		}

		// hash the password using our new salt
		void bcrypt.hash(this.password, salt, (err, hash) => {
			if (err) {
				return next(err);
			}
			// override the cleartext password with the hashed one
			this.password = hash;
			// password has now been changed and salted. set changed at
			this.pwdChangedAt = Date.now();
			next();
		});
	});
});

AdminSchema.methods.verifyPassword = function(plaintext: string) {
	logger.silly(this.password, plaintext);
	logger.silly("Verifying password");
	if (this.password === false) {
		logger.verbose("Password is false");
		return new Promise(resolve => resolve(false));
	} else {
		logger.verbose("Returning bcrypt compare");
		return bcrypt.compare(plaintext, this.password);
	}
};


const Admin: any = mongoose.model<AdminInterface>("Admin", AdminSchema);

export { Admin };