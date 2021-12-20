import express from "express";
import auth from "./routes/auth";

const app = express();

app.disable("x-powered-by");

app.use((err: express.Errback, req: express.Request, res: express.Response, next: express.NextFunction) => {
	res.status(500);
	res.json({ error: err });
	next();
});

app.use("/auth", auth);

export default app;
