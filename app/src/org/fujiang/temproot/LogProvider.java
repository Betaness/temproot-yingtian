package org.fujiang.temproot;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/** Exposes only explicitly shared immutable cache snapshots, read-only. */
public final class LogProvider extends ContentProvider {
    public static final String AUTHORITY = "org.fujiang.temproot.logs";

    @Override public boolean onCreate() { return true; }

    private File file(Uri uri) throws FileNotFoundException {
        try {
            if (!"content".equals(uri.getScheme()) || !AUTHORITY.equals(uri.getAuthority())
                    || uri.getPathSegments().size() != 1 || uri.getQuery() != null || uri.getFragment() != null)
                throw new IOException("Invalid log URI");
            File result = SessionLog.safeFile(new File(getContext().getCacheDir(), "shared-logs"),
                    uri.getLastPathSegment());
            if (!result.isFile()) throw new IOException("Log unavailable");
            return result;
        } catch (IOException e) {
            throw new FileNotFoundException("Log unavailable");
        }
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Read-only log");
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                 String[] selectionArgs, String sortOrder) {
        try {
            File f = file(uri);
            String[] columns = projection == null
                    ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
            MatrixCursor cursor = new MatrixCursor(columns);
            Object[] values = new Object[columns.length];
            for (int i = 0; i < columns.length; i++) {
                if (OpenableColumns.DISPLAY_NAME.equals(columns[i])) values[i] = f.getName();
                else if (OpenableColumns.SIZE.equals(columns[i])) values[i] = f.length();
            }
            cursor.addRow(values);
            return cursor;
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    @Override public String getType(Uri uri) { return "text/plain"; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
