package com.notes.thinknotesbackend.service;

import java.util.List;

import com.notes.thinknotesbackend.entity.AuditLog;
import com.notes.thinknotesbackend.entity.Note;

public interface AuditLogService {
    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDeletion(String username, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogsForNoteId(Long noteId);
}