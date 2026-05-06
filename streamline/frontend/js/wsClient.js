(() => {
class StreamWsClient {
  constructor(url, handlers = {}) {
    this.url = url;
    this.handlers = handlers;
    this.socket = null;
  }

  connect() {
    this.disconnect();

    this.socket = new WebSocket(this.url);

    this.socket.addEventListener("open", () => {
      if (this.handlers.onOpen) {
        this.handlers.onOpen();
      }
    });

    this.socket.addEventListener("message", (event) => {
      let payload = null;
      try {
        payload = JSON.parse(event.data);
      } catch (error) {
        if (this.handlers.onError) {
          this.handlers.onError(`Invalid server message: ${error.message}`);
        }
        return;
      }

      if (this.handlers.onMessage) {
        this.handlers.onMessage(payload);
      }
    });

    this.socket.addEventListener("close", () => {
      if (this.handlers.onClose) {
        this.handlers.onClose();
      }
    });

    this.socket.addEventListener("error", () => {
      if (this.handlers.onError) {
        this.handlers.onError("WebSocket transport error.");
      }
    });
  }

  reconnect() {
    this.connect();
  }

  disconnect() {
    if (!this.socket) {
      return;
    }
    this.socket.close();
    this.socket = null;
  }

  send(payload) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    this.socket.send(JSON.stringify(payload));
    return true;
  }
}

window.Streamline = window.Streamline || {};
window.Streamline.StreamWsClient = StreamWsClient;
})();
