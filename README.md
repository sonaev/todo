# Todo App with Subtasks

## 📋 Описание

Приложение Todo с подзадачами - это современное веб-приложение для управления задачами, построенное на FastAPI. Приложение предоставляет полную систему аутентификации, возможность сброса пароля через email, создание задач с подзадачами и их организацию с помощью drag-and-drop интерфейса.

## 🚀 Основные функции

### ✅ Система аутентификации
- Регистрация и вход пользователей
- Безопасные сессии с истечением срока (24 часа)
- Хеширование паролей SHA-256
- Защищенные маршруты с автоматическим перенаправлением

### 🔐 Восстановление пароля
- Сброс пароля через email
- Безопасные токены с истечением срока (2 часа)
- Поддержка HTML и текстовых email-сообщений
- Автоматическое удаление всех сессий после смены пароля

### 📝 Управление задачами
- Создание, редактирование и удаление задач
- Добавление описания к задачам
- Отметка выполненных задач
- Перетаскивание для изменения порядка задач

### 📋 Управление подзадачами
- Создание подзадач для каждой задачи
- Независимое управление статусом подзадач
- Перетаскивание подзадач в пределах задачи
- Автоматическое удаление подзадач при удалении основной задачи

### 🎨 Современный интерфейс
- Responsive дизайн с Tailwind CSS
- HTMX для динамического обновления без перезагрузки страницы
- Интуитивный drag-and-drop интерфейс
- Мгновенная обратная связь на действия пользователя

## 🛠 Технологический стек

- **Backend**: FastAPI (Python)
- **Database**: SQLite с SQLModel ORM
- **Frontend**: HTML + Tailwind CSS + HTMX + SortableJS
- **Authentication**: Session-based с HTTP-only cookies
- **Email**: SMTP с поддержкой различных провайдеров

## 📦 Установка и запуск

### Требования
- Python 3.8+
- pip

### Быстрый старт

1. **Клонирование и установка зависимостей:**
```bash
git clone <repository_url>
cd todo-app
pip install -r requirements.txt
```

2. **Настройка переменных окружения (опционально):**
```bash
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export FROM_EMAIL="your-email@gmail.com"
```

3. **Запуск приложения:**
```bash
uvicorn main:app --reload
```

4. **Открыть в браузере:**
```
http://localhost:8000
```

## 📧 Настройка почтовых сервисов

### Gmail

1. **Включите двухфакторную аутентификацию** в вашем Google аккаунте
2. **Создайте пароль приложения:**
   - Перейдите в Google Account Security
   - Выберите "2-Step Verification"
   - В низу страницы выберите "App passwords"
   - Выберите приложение и устройство
   - Скопируйте сгенерированный пароль

3. **Настройте переменные окружения:**
```bash
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-16-digit-app-password"
export FROM_EMAIL="your-email@gmail.com"
```

### Outlook/Hotmail

```bash
export SMTP_SERVER="smtp-mail.outlook.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@outlook.com"
export SMTP_PASSWORD="your-password"
export FROM_EMAIL="your-email@outlook.com"
```

### Yahoo Mail

1. **Включите "Less secure app access"** или используйте пароль приложения
2. **Настройте переменные:**
```bash
export SMTP_SERVER="smtp.mail.yahoo.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@yahoo.com"
export SMTP_PASSWORD="your-app-password"
export FROM_EMAIL="your-email@yahoo.com"
```

### Mail.ru

```bash
export SMTP_SERVER="smtp.mail.ru"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@mail.ru"
export SMTP_PASSWORD="your-password"
export FROM_EMAIL="your-email@mail.ru"
```

### Yandex Mail

1. **Включите "POP3 and IMAP access"** в настройках почты
2. **Настройте переменные:**
```bash
export SMTP_SERVER="smtp.yandex.ru"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@yandex.ru"
export SMTP_PASSWORD="your-password"
export FROM_EMAIL="your-email@yandex.ru"
```

### Пользовательский SMTP сервер

```bash
export SMTP_SERVER="your-smtp-server.com"
export SMTP_PORT="587"  # или 465 для SSL
export SMTP_USERNAME="your-username"
export SMTP_PASSWORD="your-password"
export FROM_EMAIL="noreply@yoursite.com"
```

## 🗄 Структура базы данных

### Таблица `user`
- `id`: UUID (Primary Key)
- `username`: String (Unique)
- `email`: String (Unique)
- `password_hash`: String (SHA-256)
- `created_at`: DateTime
- `is_active`: Boolean

### Таблица `usersession`
- `id`: UUID (Primary Key)
- `user_id`: String (Foreign Key → user.id)
- `session_token`: String (Unique)
- `expires_at`: DateTime
- `created_at`: DateTime

### Таблица `passwordreset`
- `id`: UUID (Primary Key)
- `user_id`: String (Foreign Key → user.id)
- `reset_token`: String (Unique)
- `expires_at`: DateTime
- `created_at`: DateTime
- `used`: Boolean

### Таблица `todo`
- `id`: UUID (Primary Key)
- `title`: String
- `description`: String (Optional)
- `completed`: Boolean
- `order_index`: Integer
- `created_at`: DateTime
- `user_id`: String (Foreign Key → user.id)

### Таблица `subtask`
- `id`: UUID (Primary Key)
- `title`: String
- `completed`: Boolean
- `order_index`: Integer
- `todo_id`: String (Foreign Key → todo.id)
- `created_at`: DateTime

## 🛣 API Эндпоинты

### Аутентификация

#### `GET /login`
- **Описание**: Страница входа
- **Параметры**: Нет
- **Ответ**: HTML страница входа или перенаправление на главную (если уже авторизован)

#### `POST /login`
- **Описание**: Вход в систему
- **Параметры**: 
  - `username`: String (имя пользователя или email)
  - `password`: String
- **Ответ**: Перенаправление на главную или ошибка

#### `POST /register`
- **Описание**: Регистрация нового пользователя
- **Параметры**:
  - `username`: String
  - `email`: String
  - `password`: String
  - `password_confirm`: String
- **Ответ**: Перенаправление на главную или ошибка

#### `POST /logout`
- **Описание**: Выход из системы
- **Параметры**: Нет
- **Ответ**: Перенаправление на страницу входа

#### `POST /forgot-password`
- **Описание**: Запрос сброса пароля
- **Параметры**:
  - `email`: String
- **Ответ**: Сообщение о отправке email (всегда успешное для безопасности)

#### `GET /reset-password?token={token}`
- **Описание**: Страница сброса пароля
- **Параметры**:
  - `token`: String (в query параметре)
- **Ответ**: HTML страница сброса пароля или ошибка

#### `POST /reset-password`
- **Описание**: Установка нового пароля
- **Параметры**:
  - `token`: String
  - `password`: String
  - `password_confirm`: String
- **Ответ**: Перенаправление на страницу входа или ошибка

### Задачи (Todo)

#### `GET /`
- **Описание**: Главная страница с списком задач
- **Авторизация**: Требуется
- **Ответ**: HTML страница со всеми задачами пользователя

#### `POST /todos`
- **Описание**: Создание новой задачи
- **Авторизация**: Требуется
- **Параметры**:
  - `title`: String
  - `description`: String (опционально)
- **Ответ**: HTMX частичный HTML или перенаправление

#### `POST /todos/{todo_id}/toggle`
- **Описание**: Переключение статуса выполнения задачи
- **Авторизация**: Требуется
- **Параметры**:
  - `todo_id`: String (в URL)
- **Ответ**: HTMX частичный HTML или перенаправление

#### `POST /todos/{todo_id}/delete`
- **Описание**: Удаление задачи и всех её подзадач
- **Авторизация**: Требуется
- **Параметры**:
  - `todo_id`: String (в URL)
- **Ответ**: Пустой HTML для HTMX или перенаправление

#### `POST /todos/reorder`
- **Описание**: Изменение порядка задач
- **Авторизация**: Требуется
- **Параметры**:
  - `todo_ids`: Array[String] (в JSON теле запроса)
- **Ответ**: `{"status": "success"}`

### Подзадачи (Subtasks)

#### `POST /todos/{todo_id}/subtasks`
- **Описание**: Создание новой подзадачи
- **Авторизация**: Требуется
- **Параметры**:
  - `todo_id`: String (в URL)
  - `title`: String
- **Ответ**: HTMX частичный HTML с обновленным списком подзадач

#### `POST /subtasks/{subtask_id}/toggle`
- **Описание**: Переключение статуса выполнения подзадачи
- **Авторизация**: Требуется
- **Параметры**:
  - `subtask_id`: String (в URL)
- **Ответ**: HTMX частичный HTML с обновленным списком подзадач

#### `POST /subtasks/{subtask_id}/delete`
- **Описание**: Удаление подзадачи
- **Авторизация**: Требуется
- **Параметры**:
  - `subtask_id`: String (в URL)
- **Ответ**: HTMX частичный HTML с обновленным списком подзадач

#### `POST /subtasks/reorder`
- **Описание**: Изменение порядка подзадач
- **Авторизация**: Требуется
- **Параметры**:
  - `subtask_ids`: Array[String] (в JSON теле запроса)
- **Ответ**: `{"status": "success"}`

## 📁 Структура проекта

```
todo-app/
├── main.py              # Основной файл приложения FastAPI
├── requirements.txt     # Python зависимости
├── README.md           # Документация проекта
├── templates/          # HTML шаблоны
│   ├── index.html      # Главная страница
│   ├── auth.html       # Страница аутентификации
│   ├── reset_password.html  # Страница сброса пароля
│   ├── todo_item.html  # Частичный шаблон элемента задачи
│   └── subtasks_partial.html  # Частичный шаблон подзадач
├── static/             # Статические файлы (CSS, JS, изображения)
└── todos.db           # SQLite база данных (создается автоматически)
```

## 🔒 Безопасность

### Реализованные меры безопасности:
- Хеширование паролей SHA-256
- HTTP-only cookies для сессий
- Защита от CSRF через проверку origin
- Автоматическое истечение сессий
- Безопасные токены для сброса паролей
- Проверка принадлежности данных пользователю
- Удаление всех сессий при смене пароля

### Рекомендации для продакшена:
```bash
# Установите secure cookies (требует HTTPS)
# В main.py измените secure=False на secure=True

#