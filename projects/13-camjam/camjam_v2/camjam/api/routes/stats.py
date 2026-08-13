from fastapi import APIRouter, Request

router = APIRouter(tags=["stats"])


@router.get("/stats")
async def stats(request: Request):
    return await request.app.state.session.db.stats_summary()


@router.get("/history/aps")
async def history_aps(request: Request):
    return {"access_points": await request.app.state.session.db.list_aps()}