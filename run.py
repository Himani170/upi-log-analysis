from app import app

if __name__ == "__main__":
    print("\n🛡️  UPI GUARD — Starting...\n")
    print("   Open:  http://127.0.0.1:5000")
    print("   Dash:  http://127.0.0.1:5000/dashboard")
    print("   PDF:   http://127.0.0.1:5000/export-pdf\n")
    app.run(debug=True)
