from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class ReportModel(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    scan_id: str
    report_data: Dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
