# backend/app/routers/clients.py
"""
Client CRUD Router

Endpoints:
POST   /api/v1/clients          → Register new client
GET    /api/v1/clients          → List clients (paginated)
GET    /api/v1/clients/{id}     → Get client details
PUT    /api/v1/clients/{id}     → Update client profile
DELETE /api/v1/clients/{id}     → Deactivate client (soft delete)
"""

from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional

from ..database import get_db
from ..models import Client, AuditSession as SessionModel
from ..schemas import ClientCreate, ClientResponse, ClientList
from ..dependencies import get_current_user, require_role
from ..core.exceptions import NotFoundError, ConflictError

router = APIRouter(prefix="/clients")


@router.post("", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
def create_client(
    data: ClientCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst"))
):
    """
    Register a new client for auditing.
    
    The profile_yaml field accepts the complete YAML profile as a string.
    This is the same format as the v2 file-based profiles — paste the
    contents of your .yaml file directly into this field.
    """
    # Check for duplicate name — client names must be unique
    existing = db.query(Client).filter(Client.name == data.name).first()
    if existing:
        raise ConflictError(
            f"A client named '{data.name}' already exists.",
            details={"existing_id": existing.id}
        )
    
    client = Client(
        name=data.name,
        description=data.description,
        target_url=str(data.target_url),
        target_type=data.target_type,
        profile_yaml=data.profile_yaml,
        auth_type=data.auth_type or "none",
        auth_config=data.auth_config or {}
    )
    
    db.add(client)
    db.commit()
    db.refresh(client)
    
    return client


@router.get("", response_model=ClientList)
def list_clients(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    active_only: bool = Query(True),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """List all registered clients with session count."""
    query = db.query(Client)
    
    if active_only:
        query = query.filter(Client.is_active == True)
    
    total = query.count()
    clients = query.order_by(desc(Client.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()
    
    # Enrich each client with session count
    items = []
    for client in clients:
        session_count = db.query(SessionModel).filter(
            SessionModel.client_id == client.id
        ).count()
        
        # Find last session date
        last_session = db.query(SessionModel).filter(
            SessionModel.client_id == client.id
        ).order_by(desc(SessionModel.created_at)).first()
        
        client_dict = {
            "id": client.id,
            "name": client.name,
            "description": client.description,
            "target_url": client.target_url,
            "target_type": client.target_type,
            "is_active": client.is_active,
            "created_at": client.created_at,
            "session_count": session_count,
            "last_session_at": last_session.created_at if last_session else None
        }
        items.append(client_dict)
    
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{client_id}", response_model=ClientResponse)
def get_client(
    client_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get a single client by ID."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise NotFoundError("Client", details={"id": client_id})
    return client


@router.put("/{client_id}", response_model=ClientResponse)
def update_client(
    client_id: int,
    data: ClientCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst"))
):
    """Update client profile. Used when their system changes."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise NotFoundError("Client", details={"id": client_id})
    
    client.name = data.name
    client.description = data.description
    client.target_url = str(data.target_url)
    client.target_type = data.target_type
    client.profile_yaml = data.profile_yaml
    client.auth_type = data.auth_type or "none"
    client.auth_config = data.auth_config or {}
    
    db.commit()
    db.refresh(client)
    return client


@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_client(
    client_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin"))
):
    """
    Deactivate a client (soft delete).
    
    We never hard-delete clients because their session history
    needs to remain for reporting and audit trails.
    """
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise NotFoundError("Client", details={"id": client_id})
    
    client.is_active = False
    db.commit()