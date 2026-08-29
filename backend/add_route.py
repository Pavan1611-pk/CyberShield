@app.delete("/api/scans")
def clear_all_scans(db: Session = Depends(get_db)):
    """Clear all scan records from the database for a fresh demo."""
    db.query(ScanResult).delete()
    db.commit()
    return {"status": "cleared", "message": "All scan records cleared."}
