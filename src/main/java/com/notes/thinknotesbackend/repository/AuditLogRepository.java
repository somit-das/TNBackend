package com.notes.thinknotesbackend.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.notes.thinknotesbackend.entity.AuditLog;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByNoteId(Long noteId);
}