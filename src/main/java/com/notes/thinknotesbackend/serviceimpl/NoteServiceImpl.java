package com.notes.thinknotesbackend.serviceimpl;

import com.notes.thinknotesbackend.entity.Note;
import com.notes.thinknotesbackend.repository.NoteRepository;
import com.notes.thinknotesbackend.service.AuditLogService;
import com.notes.thinknotesbackend.service.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NoteServiceImpl implements NoteService {
    @Autowired
    private NoteRepository noteRepository;
    @Autowired
    private AuditLogService auditLogService;

    @Override
    public Note createNoteForUser(String username, String content) {
        Note note = new Note();
        note.setContent(content);
        note.setOwnerUsername(username);
        Note savedNote = noteRepository.save(note);
        auditLogService.logNoteCreation(username, note);
        return savedNote;
    }

    @Override
    public Note updateNoteForUser(Long noteId, String content, String username) {
        Note foundNote = noteRepository.findById(noteId).orElseThrow(()
                -> new RuntimeException("Note not found"));
        foundNote.setContent(content);
        Note updatedNote = noteRepository.save(foundNote);

        auditLogService.logNoteUpdate(username, foundNote);
        return updatedNote;
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        Note note = noteRepository.findById(noteId).orElseThrow(
                () -> new RuntimeException("Note not found")
        );
        auditLogService.logNoteDeletion(username, noteId);
        noteRepository.delete(note);
    }

    @Override
    public List<Note> getNotesForUser(String username) {
        List<Note> personalNotes = noteRepository
                .findByOwnerUsername(username);
        return personalNotes;
    }
}
