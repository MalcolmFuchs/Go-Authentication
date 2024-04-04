Session Cookie nutzen
- Redis
- Cryptografisch Token erstellen -> CSPRNG
  https://blog.questionable.services/article/generating-secure-random-numbers-crypto-rand/
- 128bit = 16 Byte von Go geben und encodest die dann mit base64
- Cookie verteilen mit Dauer
- Bei jeder Request Cookie mitschicken

- User PW in Datenbank abfragen

- ExpiresAt Cookie auf dem Serverlöschen
- go-routine Sleep nach ablauf der Zeit cookie wird gelöscht aus Session Storage
- mutex!!!

- context api in middleware isAuthorized um zu schauen ob Cookie gesetzt ist falls nicht dann 403