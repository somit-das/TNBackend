package com.notes.thinknotesbackend.service;

import com.notes.thinknotesbackend.entity.Note;

import java.util.List;

public interface NoteService {
    Note createNoteForUser(String username, String content);
    Note updateNoteForUser(Long noteId, String username, String content);

    void deleteNoteForUser(Long noteId, String username);
    List<Note> getAllNotesForUser(String username);
}
