import { Server } from "http";
import { Server as SocketServer } from "socket.io";

const http = new Server((request, response) => response.end("ok"));
const io = new SocketServer(http);
io.on("connection", () => undefined);
http.listen(8000);
