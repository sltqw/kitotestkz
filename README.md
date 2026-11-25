# KITOTEST — Render deployment

## Құрылымы
- `server.js` — Express API, аккаунттар, админ панелі, аноним чат және Socket.IO.
- `public/index.html` — сайттың интерфейсі.
- `package.json` — сервер тәуелділіктері және іске қосу командасы.
- `render.yaml` — Render конфигурациясы және тұрақты диск.
- `.env.example` — жергілікті ортаға арналған үлгі. Нақты `.env` файлын GitHub-қа салмаңыз.

## Render арқылы орналастыру
1. Осы папканың ішіндегі барлық файлды GitHub репозиторийінің түбіріне жүктеңіз.
2. Render → New → Blueprint таңдаңыз да, репозиторийді қосыңыз. Немесе Web Service жасап, Build Command: `npm install`, Start Command: `npm start` деп қойыңыз.
3. `render.yaml` пайдаланылса, Render тұрақты дискіні `/var/data` жолына жалғап, `DATA_DIR` орнатады. Бұл тіркелген аккаунттар мен чат деректерін қайта deploy жасағанда сақтауға қажет.
4. Render Environment бөлімінде `JWT_SECRET` кемінде 32 таңбалы кездейсоқ мән болсын. `ADMIN_CODE` мәнін `111` қалдыруға немесе өзіңіз ауыстыруға болады.
5. Google кіруін қоспасаңыз, `GOOGLE_CLIENT_ID` бос қалуы мүмкін. Қосу үшін Google OAuth Web Client ID енгізіп, HTML-дегі `window.KITOTEST_GOOGLE_CLIENT_ID` мәнін сол ID-ге орнатыңыз.

## Жергілікті іске қосу
`npm install` → `.env.example` файлын `.env` деп көшіріп, `JWT_SECRET` мәнін өзгертіңіз → `npm start`.

Админ коды әдепкіде `111`. Админ оқушылардың email-ін көреді және құпиясөзін жаңасына ауыстыра алады; ескі құпиясөз хэш түрінде сақталады және көрсетілмейді.
