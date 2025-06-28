from fastapi import FastAPI, Form, Request, HTTPException, Depends, Cookie
from contextlib import asynccontextmanager
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import SQLModel, Field, create_engine, Session, select
from typing import Optional, Annotated
import uuid
from datetime import datetime, timedelta
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Database Models
class User(SQLModel, table=True):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.now)
    is_active: bool = Field(default=True)

class UserSession(SQLModel, table=True):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_id: str = Field(foreign_key="user.id")
    session_token: str = Field(unique=True, index=True)
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.now)

class PasswordReset(SQLModel, table=True):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_id: str = Field(foreign_key="user.id")
    reset_token: str = Field(unique=True, index=True)
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.now)
    used: bool = Field(default=False)

class TodoBase(SQLModel):
    title: str
    description: Optional[str] = None
    completed: bool = False
    order_index: int = 0
    created_at: datetime = Field(default_factory=datetime.now)
    user_id: str = Field(foreign_key="user.id")

class Todo(TodoBase, table=True):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)

class SubtaskBase(SQLModel):
    title: str
    completed: bool = False
    order_index: int = 0
    todo_id: str = Field(foreign_key="todo.id")
    created_at: datetime = Field(default_factory=datetime.now)

class Subtask(SubtaskBase, table=True):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)

# Database setup
engine = create_engine("sqlite:///todos.db")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# Password hashing
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

# Session management
def create_session_token() -> str:
    return secrets.token_urlsafe(32)

def get_current_user(session_token: Annotated[str | None, Cookie()] = None) -> Optional[User]:
    if not session_token:
        return None
    
    with Session(engine) as session:
        # Check if session exists and is valid
        user_session = session.exec(
            select(UserSession).where(
                UserSession.session_token == session_token,
                UserSession.expires_at > datetime.now()
            )
        ).first()
        
        if not user_session:
            return None
        
        # Get user
        user = session.get(User, user_session.user_id)
        return user

def require_auth(current_user: Annotated[User | None, Depends(get_current_user)]):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user

# Email configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USERNAME)

def send_password_reset_email(email: str, reset_token: str, request: Request):
    """Отправляет email с ссылкой для сброса пароля"""
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        print("SMTP настройки не настроены")
        return False
    
    try:
        # Создаем ссылку для сброса пароля
        reset_url = f"{request.url.scheme}://{request.url.netloc}/reset-password?token={reset_token}"
        
        # Создаем сообщение
        message = MIMEMultipart("alternative")
        message["Subject"] = "Восстановление пароля"
        message["From"] = FROM_EMAIL
        message["To"] = email
        
        # HTML версия письма
        html = f"""
        <html>
          <body>
            <h2>Восстановление пароля</h2>
            <p>Вы запросили восстановление пароля для вашего аккаунта.</p>
            <p>Для установки нового пароля перейдите по ссылке:</p>
            <p><a href="{reset_url}">Восстановить пароль</a></p>
            <p>Для безопасности эта ссылка действует только 2 часа.</p>
            <p>Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.</p>
          </body>
        </html>
        """
        
        # Текстовая версия
        text = f"""
        Восстановление пароля
        
        Вы запросили восстановление пароля для вашего аккаунта.
        
        Для установки нового пароля перейдите по ссылке:
        {reset_url}
        
        Для безопасности эта ссылка действует только 2 часа.
        
        Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.
        """
        
        # Добавляем части сообщения
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        
        message.attach(part1)
        message.attach(part2)
        
        # Отправляем email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
        
        return True
    except Exception as e:
        print(f"Ошибка отправки email: {e}")
        return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_db_and_tables()
    yield
    # Shutdown (если нужно что-то делать при завершении)

# FastAPI app
app = FastAPI(title="Todo App with Subtasks", lifespan=lifespan)

# Static files and templates
templates = Jinja2Templates(directory="templates")

# Exception handler для перенаправления неавторизованных пользователей
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        # Если это AJAX запрос, возвращаем JSON
        accept_header = request.headers.get("accept", "")
        if "application/json" in accept_header or "text/javascript" in accept_header:
            return {"detail": exc.detail, "redirect": "/login"}
        # Иначе перенаправляем на страницу входа
        return RedirectResponse(url="/login", status_code=302)
    # Для других ошибок возвращаем стандартный обработчик
    return {"detail": exc.detail}

# Authentication Routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, current_user: Annotated[User | None, Depends(get_current_user)] = None):
    if current_user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("auth.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with Session(engine) as session:
        # Find user by username or email
        user = session.exec(
            select(User).where(
                (User.username == username) | (User.email == username)
            )
        ).first()
        
        if not user or not verify_password(password, user.password_hash):
            return templates.TemplateResponse("auth.html", {
                "request": request, 
                "error": "Неверное имя пользователя или пароль"
            })
        
        # Create session
        session_token = create_session_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        session.add(user_session)
        session.commit()
        
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session_token",
            value=session_token,
            max_age=24 * 60 * 60,  # 24 hours
            httponly=True,
            secure=False  # Set to True in production with HTTPS
        )
        return response

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str):
    with Session(engine) as session:
        # Проверяем действительность токена
        password_reset = session.exec(
            select(PasswordReset).where(
                PasswordReset.reset_token == token,
                PasswordReset.expires_at > datetime.now(),
                PasswordReset.used == False
            )
        ).first()
        
        if not password_reset:
            return templates.TemplateResponse("auth.html", {
                "request": request,
                "error": "Ссылка для сброса пароля недействительна или истекла"
            })
        
        # Получаем пользователя
        user = session.get(User, password_reset.user_id)
        if not user:
            return templates.TemplateResponse("auth.html", {
                "request": request,
                "error": "Пользователь не найден"
            })
    
    return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "token": token,
        "email": user.email
    })

@app.post("/reset-password")
async def reset_password(request: Request, token: str = Form(...), password: str = Form(...), password_confirm: str = Form(...)):
    if password != password_confirm:
        return templates.TemplateResponse("reset_password.html", {
            "request": request,
            "token": token,
            "error": "Пароли не совпадают"
        })
    
    if len(password) < 6:
        return templates.TemplateResponse("reset_password.html", {
            "request": request,
            "token": token,
            "error": "Пароль должен содержать минимум 6 символов"
        })
    
    with Session(engine) as session:
        # Проверяем действительность токена
        password_reset = session.exec(
            select(PasswordReset).where(
                PasswordReset.reset_token == token,
                PasswordReset.expires_at > datetime.now(),
                PasswordReset.used == False
            )
        ).first()
        
        if not password_reset:
            return templates.TemplateResponse("reset_password.html", {
                "request": request,
                "token": token,
                "error": "Ссылка для сброса пароля недействительна или истекла"
            })
        
        # Получаем пользователя и обновляем пароль
        user = session.get(User, password_reset.user_id)
        if not user:
            return templates.TemplateResponse("reset_password.html", {
                "request": request,
                "token": token,
                "error": "Пользователь не найден"
            })
        
        # Обновляем пароль
        user.password_hash = hash_password(password)
        session.add(user)
        
        # Помечаем токен как использованный
        password_reset.used = True
        session.add(password_reset)
        
        # Удаляем все активные сессии пользователя для безопасности
        user_sessions = session.exec(
            select(UserSession).where(UserSession.user_id == user.id)
        ).all()
        for user_session in user_sessions:
            session.delete(user_session)
        
        session.commit()
    
    return templates.TemplateResponse("auth.html", {
        "request": request,
        "success": "Пароль успешно изменен. Войдите в систему с новым паролем."
    })

@app.post("/register")
async def register(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...), password_confirm: str = Form(...)):
    if password != password_confirm:
        return templates.TemplateResponse("auth.html", {
            "request": request,
            "error": "Пароли не совпадают"
        })
    
    with Session(engine) as session:
        # Check if user exists
        existing_user = session.exec(
            select(User).where(
                (User.username == username) | (User.email == email)
            )
        ).first()
        
        if existing_user:
            return templates.TemplateResponse("auth.html", {
                "request": request,
                "error": "Пользователь с таким именем или email уже существует"
            })
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password)
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        
        # Create session
        session_token = create_session_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        session.add(user_session)
        session.commit()
        
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session_token",
            value=session_token,
            max_age=24 * 60 * 60,
            httponly=True,
            secure=False
        )
        return response

@app.post("/logout")
async def logout(request: Request, session_token: Annotated[str | None, Cookie()] = None):
    if session_token:
        with Session(engine) as session:
            user_session = session.exec(
                select(UserSession).where(UserSession.session_token == session_token)
            ).first()
            if user_session:
                session.delete(user_session)
                session.commit()
    
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_token")
    return response

@app.post("/forgot-password")
async def forgot_password(request: Request, email: str = Form(...)):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        
        if not user:
            return templates.TemplateResponse("auth.html", {
                "request": request,
                "success": "Если указанный email существует, на него было отправлено письмо для сброса пароля"
            })
        
        # Create reset token
        reset_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=2)
        
        password_reset = PasswordReset(
            user_id=user.id,
            reset_token=reset_token,
            expires_at=expires_at
        )
        session.add(password_reset)
        session.commit()
        
        # Отправляем email с инструкциями
        email_sent = send_password_reset_email(user.email, reset_token, request)
        
        # Всегда показываем успешное сообщение для безопасности
        return templates.TemplateResponse("auth.html", {
            "request": request,
            "success": "Если указанный email существует, на него было отправлено письмо для сброса пароля"
        })

# Protected Routes
@app.get("/", response_class=HTMLResponse)
async def read_todos(request: Request, current_user: Annotated[User, Depends(require_auth)]):
    with Session(engine) as session:
        todos = session.exec(
            select(Todo).where(Todo.user_id == current_user.id).order_by(Todo.order_index.asc())
        ).all()
        todos_with_subtasks = []
        
        for todo in todos:
            subtasks = session.exec(
                select(Subtask).where(Subtask.todo_id == todo.id).order_by(Subtask.order_index.asc())
            ).all()
            todos_with_subtasks.append({"todo": todo, "subtasks": subtasks})
    
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "todos_with_subtasks": todos_with_subtasks,
        "current_user": current_user
    })

@app.post("/todos")
async def create_todo(request: Request, title: str = Form(...), description: str = Form(""), current_user: Annotated[User, Depends(require_auth)] = None):
    with Session(engine) as session:
        # Increment order_index for all existing todos
        existing_todos = session.exec(
            select(Todo).where(Todo.user_id == current_user.id)
        ).all()
        for existing_todo in existing_todos:
            existing_todo.order_index += 1
            session.add(existing_todo)
        
        # Create new todo with order_index = 0 (at the top)
        todo = Todo(title=title, description=description, order_index=0, user_id=current_user.id)
        session.add(todo)
        session.commit()
        session.refresh(todo)
        
        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Get subtasks for the new todo (empty list)
            subtasks = []
            todo_with_subtasks = {"todo": todo, "subtasks": subtasks}
            return templates.TemplateResponse("todo_item.html", {
                "request": request, 
                "item": todo_with_subtasks
            })
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/todos/{todo_id}/subtasks")
async def create_subtask(request: Request, todo_id: str, title: str = Form(...), current_user: Annotated[User, Depends(require_auth)] = None):
    with Session(engine) as session:
        # Check if todo exists and belongs to user
        todo = session.exec(
            select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
        ).first()
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        # Increment order_index for all existing subtasks
        existing_subtasks = session.exec(
            select(Subtask).where(Subtask.todo_id == todo_id)
        ).all()
        for existing_subtask in existing_subtasks:
            existing_subtask.order_index += 1
            session.add(existing_subtask)
        
        # Create new subtask with order_index = 0 (at the top)
        subtask = Subtask(title=title, todo_id=todo_id, order_index=0)
        session.add(subtask)
        session.commit()
        
        # Return updated subtasks list for HTMX
        subtasks = session.exec(
            select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index.asc())
        ).all()
    
    return templates.TemplateResponse("subtasks_partial.html", {
        "request": request,
        "subtasks": subtasks,
        "todo_id": todo_id
    })

@app.post("/todos/{todo_id}/toggle")
async def toggle_todo(request: Request, todo_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    with Session(engine) as session:
        todo = session.exec(
            select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
        ).first()
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        todo.completed = not todo.completed
        session.add(todo)
        session.commit()
        
        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Get subtasks for the todo
            subtasks = session.exec(
                select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index.asc())
            ).all()
            todo_with_subtasks = {"todo": todo, "subtasks": subtasks}
            return templates.TemplateResponse("todo_item.html", {
                "request": request, 
                "item": todo_with_subtasks
            })
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/subtasks/{subtask_id}/toggle")
async def toggle_subtask(request: Request, subtask_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    with Session(engine) as session:
        # Get subtask and verify it belongs to user's todo
        subtask = session.exec(
            select(Subtask).join(Todo).where(
                Subtask.id == subtask_id,
                Todo.user_id == current_user.id
            )
        ).first()
        if not subtask:
            raise HTTPException(status_code=404, detail="Subtask not found")
        
        subtask.completed = not subtask.completed
        session.add(subtask)
        session.commit()
        
        # Return updated subtasks list for HTMX
        subtasks = session.exec(
            select(Subtask).where(Subtask.todo_id == subtask.todo_id).order_by(Subtask.order_index.asc())
        ).all()
    
    return templates.TemplateResponse("subtasks_partial.html", {
        "request": request,
        "subtasks": subtasks,
        "todo_id": subtask.todo_id
    })

@app.post("/todos/{todo_id}/delete")
async def delete_todo(request: Request, todo_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    with Session(engine) as session:
        # Check if todo belongs to user
        todo = session.exec(
            select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
        ).first()
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        # Delete subtasks first
        subtasks = session.exec(select(Subtask).where(Subtask.todo_id == todo_id)).all()
        for subtask in subtasks:
            session.delete(subtask)
        
        # Delete todo
        session.delete(todo)
        session.commit()
    
    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse("")  # Return empty response for HTMX to remove element
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/subtasks/{subtask_id}/delete")
async def delete_subtask(request: Request, subtask_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    with Session(engine) as session:
        # Get subtask and verify it belongs to user's todo
        subtask = session.exec(
            select(Subtask).join(Todo).where(
                Subtask.id == subtask_id,
                Todo.user_id == current_user.id
            )
        ).first()
        todo_id = subtask.todo_id if subtask else None
        
        if subtask:
            session.delete(subtask)
            session.commit()
        
        # Return updated subtasks list for HTMX
        if todo_id:
            subtasks = session.exec(
                select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index.asc())
            ).all()
            return templates.TemplateResponse("subtasks_partial.html", {
                "request": request,
                "subtasks": subtasks,
                "todo_id": todo_id
            })
    
    return HTMLResponse("")

@app.post("/todos/reorder")
async def reorder_todos(request: Request, current_user: Annotated[User, Depends(require_auth)] = None):
    data = await request.json()
    todo_ids = data.get("todo_ids", [])
    
    with Session(engine) as session:
        for index, todo_id in enumerate(todo_ids):
            todo = session.exec(
                select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
            ).first()
            if todo:
                todo.order_index = index
                session.add(todo)
        session.commit()
    
    return {"status": "success"}

@app.post("/subtasks/reorder")
async def reorder_subtasks(request: Request, current_user: Annotated[User, Depends(require_auth)] = None):
    data = await request.json()
    subtask_ids = data.get("subtask_ids", [])
    
    with Session(engine) as session:
        for index, subtask_id in enumerate(subtask_ids):
            # Verify subtask belongs to user's todo
            subtask = session.exec(
                select(Subtask).join(Todo).where(
                    Subtask.id == subtask_id,
                    Todo.user_id == current_user.id
                )
            ).first()
            if subtask:
                subtask.order_index = index
                session.add(subtask)
        session.commit()
    
    return {"status": "success"}