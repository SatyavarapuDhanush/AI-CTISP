from app.server import app, init_db

if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)