# Mon Projet FAF (Form-a-Friend)

## Installation 
```bash
npm install
npm start

frontend/ : pages HTML, CSS et JS
backend/ : serveur Express

## API
Attend un JSON { nom, email, message }.
Répond { message: "Votre message a été enregistré" }.
GET /admin
Renvoie la liste JSON des objets déposés.