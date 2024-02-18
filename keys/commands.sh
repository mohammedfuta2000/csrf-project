openssl genpkey -algorithm RSA -out app.rsa
openssl rsa -pubout -in app.rsa -out app.rsa.pub
