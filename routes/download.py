"""
SubZero Project Source Zip Download Blueprint.
Bundles project assets into an on-demand, cache-validated zip archive.
"""
__author__ = "SubZero Community"

import os
from pathlib import Path
import zipfile

from flask import Blueprint, send_file

download_bp = Blueprint('download', __name__)


def _generate_project_zip(output_path: Path) -> None:
    # Resolve to root repository directory
    project_dir = Path(__file__).resolve().parents[1]
    exclude_dirs = {'__pycache__', '.git', '.runtime', '.pytest_cache', '.venv'}
    exclude_extensions = {'.pyc', '.pyo', '.zip'}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_zip = output_path.with_suffix('.tmp')
    with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                if any(f.endswith(ext) for ext in exclude_extensions):
                    continue
                file_path = Path(root) / f
                arcname = file_path.relative_to(project_dir.parent)
                zf.write(file_path, arcname)
    if output_path.exists():
        try:
            output_path.unlink()
        except Exception:
            pass
    temp_zip.replace(output_path)


def _is_zip_stale(zip_path: Path, project_dir: Path) -> bool:
    """Checks whether the cached zip is missing or older than any source file in the project."""
    if not zip_path.is_file():
        return True
    try:
        zip_mtime = zip_path.stat().st_mtime
        exclude_dirs = {'__pycache__', '.git', '.runtime', '.pytest_cache', '.venv'}
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                if f.endswith(('.py', '.html', '.css', '.js', '.md', '.bat', '.sh', '.txt')):
                    if (Path(root) / f).stat().st_mtime > zip_mtime:
                        return True
        return False
    except Exception:
        return True


@download_bp.get('/api/download/zip')
def download_project_zip():
    """Provides instant one-click download of the complete project as a zip file with latest changes."""
    project_dir = Path(__file__).resolve().parents[1]
    zip_path = project_dir.parent / 'SubZero_Pro.zip'
    if _is_zip_stale(zip_path, project_dir):
        _generate_project_zip(zip_path)
    return send_file(
        str(zip_path),
        mimetype='application/zip',
        as_attachment=True,
        download_name='SubZero_Pro.zip'
    )
