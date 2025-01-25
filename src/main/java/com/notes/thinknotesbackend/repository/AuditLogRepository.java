package com.notes.thinknotesbackend.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.notes.thinknotesbackend.entity.AuditLog;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByNoteId(Long noteId);
}