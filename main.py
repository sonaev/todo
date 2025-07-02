from fastapi import FastAPI, Form, Request, HTTPException, Depends, Cookie
from contextlib import asynccontextmanager
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import SQLModel, Field, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
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

# Async database setup
engine = create_async_engine("sqlite+aiosqlite:///todos.db")
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

# Password hashing
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

# Session management
def create_session_token() -> str:
    return secrets.token_urlsafe(32)

async def get_current_user(session_token: Annotated[str | None, Cookie()] = None) -> Optional[User]:
    if not session_token:
        return None
    
    async with async_session() as session:
        # Check if session exists and is valid
        result = await session.execute(
            select(UserSession).where(
                UserSession.session_token == session_token,
                UserSession.expires_at > datetime.now()
            )
        )
        user_session = result.scalar_one_or_none()
        
        if not user_session:
            return None
        
        # Get user
        user = await session.get(User, user_session.user_id)
        return user

async def require_auth(current_user: Annotated[User | None, Depends(get_current_user)]):
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
    await create_db_and_tables()
    yield
    # Shutdown
    await engine.dispose()

# FastAPI app
app = FastAPI(title="Segmentum Api", lifespan=lifespan)

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
    async with async_session() as session:
        # Find user by username or email
        result = await session.execute(
            select(User).where(
                (User.username == username) | (User.email == username)
            )
        )
        user = result.scalar_one_or_none()
        
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
        await session.commit()
        
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
    async with async_session() as session:
        # Проверяем действительность токена
        result = await session.execute(
            select(PasswordReset).where(
                PasswordReset.reset_token == token,
                PasswordReset.expires_at > datetime.now(),
                PasswordReset.used == False
            )
        )
        password_reset = result.scalar_one_or_none()
        
        if not password_reset:
            return templates.TemplateResponse("auth.html", {
                "request": request,
                "error": "Ссылка для сброса пароля недействительна или истекла"
            })
        
        # Получаем пользователя
        user = await session.get(User, password_reset.user_id)
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
    
    async with async_session() as session:
        # Проверяем действительность токена
        result = await session.execute(
            select(PasswordReset).where(
                PasswordReset.reset_token == token,
                PasswordReset.expires_at > datetime.now(),
                PasswordReset.used == False
            )
        )
        password_reset = result.scalar_one_or_none()
        
        if not password_reset:
            return templates.TemplateResponse("reset_password.html", {
                "request": request,
                "token": token,
                "error": "Ссылка для сброса пароля недействительна или истекла"
            })
        
        # Получаем пользователя и обновляем пароль
        user = await session.get(User, password_reset.user_id)
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
        result = await session.execute(
            select(UserSession).where(UserSession.user_id == user.id)
        )
        user_sessions = result.scalars().all()
        for user_session in user_sessions:
            await session.delete(user_session)
        
        await session.commit()
    
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
    
    async with async_session() as session:
        # Check if user exists
        result = await session.execute(
            select(User).where(
                (User.username == username) | (User.email == email)
            )
        )
        existing_user = result.scalar_one_or_none()
        
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
        await session.commit()
        
        # Create session
        session_token = create_session_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        session.add(user_session)
        await session.commit()
        
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
        async with async_session() as session:
            result = await session.execute(
                select(UserSession).where(UserSession.session_token == session_token)
            )
            user_session = result.scalar_one_or_none()
            if user_session:
                await session.delete(user_session)
                await session.commit()
    
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_token")
    return response

@app.post("/forgot-password")
async def forgot_password(request: Request, email: str = Form(...)):
    async with async_session() as session:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
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
        await session.commit()
        
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
    async with async_session() as session:
        result = await session.execute(
            select(Todo).where(Todo.user_id == current_user.id).order_by(Todo.order_index.asc())
        )
        todos = result.scalars().all()
        todos_with_subtasks = []
        
        for todo in todos:
            result = await session.execute(
                select(Subtask).where(Subtask.todo_id == todo.id).order_by(Subtask.order_index.asc())
            )
            subtasks = result.scalars().all()
            todos_with_subtasks.append({"todo": todo, "subtasks": subtasks})
    
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "todos_with_subtasks": todos_with_subtasks,
        "current_user": current_user
    })

@app.post("/todos")
async def create_todo(request: Request, title: str = Form(...), description: str = Form(""), current_user: Annotated[User, Depends(require_auth)] = None):
    async with async_session() as session:
        # Increment order_index for all existing todos
        result = await session.execute(
            select(Todo).where(Todo.user_id == current_user.id)
        )
        existing_todos = result.scalars().all()
        for existing_todo in existing_todos:
            existing_todo.order_index += 1
            session.add(existing_todo)
        
        # Create new todo with order_index = 0 (at the top)
        todo = Todo(title=title, description=description, order_index=0, user_id=current_user.id)
        session.add(todo)
        await session.commit()
        await session.refresh(todo)
        
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
    async with async_session() as session:
        # Check if todo exists and belongs to user
        result = await session.execute(
            select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
        )
        todo = result.scalar_one_or_none()
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        # Increment order_index for all existing subtasks
        result = await session.execute(
            select(Subtask).where(Subtask.todo_id == todo_id)
        )
        existing_subtasks = result.scalars().all()
        for existing_subtask in existing_subtasks:
            existing_subtask.order_index += 1
            session.add(existing_subtask)
        
        # Create new subtask with order_index = 0 (at the top)
        subtask = Subtask(title=title, todo_id=todo_id, order_index=0)
        session.add(subtask)
        await session.commit()
        
        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Get updated todo and subtasks for HTMX response
            result = await session.execute(
                select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index.asc())
            )
            subtasks = result.scalars().all()
            todo_with_subtasks = {"todo": todo, "subtasks": subtasks}
            return templates.TemplateResponse("todo_item.html", {
                "request": request, 
                "item": todo_with_subtasks
            })
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/todos/{todo_id}/toggle")
async def toggle_todo(request: Request, todo_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    async with async_session() as session:
        result = await session.execute(
            select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
        )
        todo = result.scalar_one_or_none()
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        # Get subtasks for this todo
        result = await session.execute(
            select(Subtask).where(Subtask.todo_id == todo_id)
        )
        subtasks = result.scalars().all()
        
        # If trying to mark todo as completed but has incomplete subtasks, prevent it
        if not todo.completed and subtasks:
            incomplete_subtasks = [s for s in subtasks if not s.completed]
            if incomplete_subtasks:
                # Don't toggle, keep todo incomplete
                pass
            else:
                # All subtasks are completed, allow toggling
                todo.completed = not todo.completed
                session.add(todo)
        elif todo.completed:
            # Allow unchecking completed todo
            todo.completed = not todo.completed
            session.add(todo)
        elif not subtasks:
            # No subtasks, allow normal toggling
            todo.completed = not todo.completed
            session.add(todo)
        
        await session.commit()
        
        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Get updated subtasks for the todo
            result = await session.execute(
                select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index.asc())
            )
            subtasks = result.scalars().all()
            todo_with_subtasks = {"todo": todo, "subtasks": subtasks}
            return templates.TemplateResponse("todo_item.html", {
                "request": request, 
                "item": todo_with_subtasks
            })
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/subtasks/{subtask_id}/toggle")
async def toggle_subtask(request: Request, subtask_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    async with async_session() as session:
        # Get subtask and verify it belongs to user's todo
        result = await session.execute(
            select(Subtask).join(Todo).where(
                Subtask.id == subtask_id,
                Todo.user_id == current_user.id
            )
        )
        subtask = result.scalar_one_or_none()
        if not subtask:
            raise HTTPException(status_code=404, detail="Subtask not found")
        
        subtask.completed = not subtask.completed
        session.add(subtask)
        
        # Get the parent todo
        todo = await session.get(Todo, subtask.todo_id)
        
        # Check if all subtasks are completed after this change
        result = await session.execute(
            select(Subtask).where(Subtask.todo_id == subtask.todo_id)
        )
        all_subtasks = result.scalars().all()
        
        # Auto-complete parent todo if all subtasks are completed
        if all_subtasks and all(s.completed for s in all_subtasks):
            todo.completed = True
            session.add(todo)
        # Auto-uncomplete parent todo if any subtask becomes incomplete
        elif todo.completed and any(not s.completed for s in all_subtasks):
            todo.completed = False
            session.add(todo)
        
        await session.commit()
        
        # Return updated todo item for HTMX
        result = await session.execute(
            select(Subtask).where(Subtask.todo_id == subtask.todo_id).order_by(Subtask.order_index.asc())
        )
        subtasks = result.scalars().all()
        todo_with_subtasks = {"todo": todo, "subtasks": subtasks}
    
    return templates.TemplateResponse("todo_item.html", {
        "request": request,
        "item": todo_with_subtasks
    })

@app.get("/todos/{todo_id}/view")
async def view_todo_public(request: Request, todo_id: str):
    """Public read-only view of a todo with its subtasks"""
    async with async_session() as session:
        # Get todo (no user authentication required for public view)
        todo = await session.get(Todo, todo_id)
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        # Get subtasks
        result = await session.execute(
            select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index, Subtask.created_at)
        )
        subtasks = result.scalars().all()
        
        # Create the same structure as in main page
        todo_with_subtasks = {
            "todo": todo,
            "subtasks": subtasks
        }
    
    return templates.TemplateResponse("todo_view_public.html", {
        "request": request,
        "item": todo_with_subtasks
    })

@app.post("/todos/{todo_id}/delete")
async def delete_todo(request: Request, todo_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    async with async_session() as session:
        # Check if todo belongs to user
        result = await session.execute(
            select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
        )
        todo = result.scalar_one_or_none()
        if not todo:
            raise HTTPException(status_code=404, detail="Todo not found")
        
        # Delete subtasks first
        result = await session.execute(select(Subtask).where(Subtask.todo_id == todo_id))
        subtasks = result.scalars().all()
        for subtask in subtasks:
            await session.delete(subtask)
        
        # Delete todo
        await session.delete(todo)
        await session.commit()
    
    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse("")  # Return empty response for HTMX to remove element
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/subtasks/{subtask_id}/delete")
async def delete_subtask(request: Request, subtask_id: str, current_user: Annotated[User, Depends(require_auth)] = None):
    async with async_session() as session:
        # Get subtask and verify it belongs to user's todo
        result = await session.execute(
            select(Subtask).join(Todo).where(
                Subtask.id == subtask_id,
                Todo.user_id == current_user.id
            )
        )
        subtask = result.scalar_one_or_none()
        todo_id = subtask.todo_id if subtask else None
        
        if subtask:
            await session.delete(subtask)
            
            # Get the parent todo
            todo = await session.get(Todo, todo_id)
            
            # Check remaining subtasks after deletion
            result = await session.execute(
                select(Subtask).where(Subtask.todo_id == todo_id)
            )
            remaining_subtasks = result.scalars().all()
            
            # Auto-complete parent todo if all remaining subtasks are completed
            if remaining_subtasks and all(s.completed for s in remaining_subtasks):
                todo.completed = True
                session.add(todo)
            # If no subtasks left, allow manual completion again
            elif not remaining_subtasks:
                # Keep current completion status but allow manual toggling again
                pass
            
            await session.commit()
        
        # Return updated todo item for HTMX
        if todo_id:
            result = await session.execute(
                select(Subtask).where(Subtask.todo_id == todo_id).order_by(Subtask.order_index.asc())
            )
            subtasks = result.scalars().all()
            todo_with_subtasks = {"todo": todo, "subtasks": subtasks}
            return templates.TemplateResponse("todo_item.html", {
                "request": request,
                "item": todo_with_subtasks
            })
    
    return HTMLResponse("")

@app.post("/todos/reorder")
async def reorder_todos(request: Request, current_user: Annotated[User, Depends(require_auth)] = None):
    data = await request.json()
    todo_ids = data.get("todo_ids", [])
    
    async with async_session() as session:
        for index, todo_id in enumerate(todo_ids):
            result = await session.execute(
                select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)
            )
            todo = result.scalar_one_or_none()
            if todo:
                todo.order_index = index
                session.add(todo)
        await session.commit()
    
    return {"status": "success"}

@app.post("/subtasks/reorder")
async def reorder_subtasks(request: Request, current_user: Annotated[User, Depends(require_auth)] = None):
    data = await request.json()
    subtask_ids = data.get("subtask_ids", [])
    
    async with async_session() as session:
        for index, subtask_id in enumerate(subtask_ids):
            # Verify subtask belongs to user's todo
            result = await session.execute(
                select(Subtask).join(Todo).where(
                    Subtask.id == subtask_id,
                    Todo.user_id == current_user.id
                )
            )
            subtask = result.scalar_one_or_none()
            if subtask:
                subtask.order_index = index
                session.add(subtask)
        await session.commit()
    
    return {"status": "success"}