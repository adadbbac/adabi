-- الأدب العربي في البكالوريا 2.0
-- قاعدة البيانات المركزية: Cloudflare D1 / SQLite
-- هذا المخطط يهيئ المنصة لكل الوظائف المشتركة، مع إبقاء النسخة 1.0 مستقلة.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  school TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  class_name TEXT DEFAULT 'آداب',
  progress INTEGER NOT NULL DEFAULT 0,
  mission TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_students_phone ON students(phone);
CREATE INDEX IF NOT EXISTS idx_students_status ON students(status);

-- المحتوى القابل للإدارة مستقبلا من فضاء الأستاذ.
CREATE TABLE IF NOT EXISTS content_items (
  id TEXT PRIMARY KEY,
  axis_no INTEGER NOT NULL CHECK(axis_no BETWEEN 1 AND 5),
  kind TEXT NOT NULL CHECK(kind IN ('lesson','training','research')),
  title TEXT NOT NULL,
  slug TEXT,
  summary TEXT,
  body_html TEXT,
  source_url TEXT,
  source_mode TEXT NOT NULL DEFAULT 'static' CHECK(source_mode IN ('static','dynamic','external')),
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
  order_index INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_content_axis_kind ON content_items(axis_no,kind,status,order_index);
CREATE INDEX IF NOT EXISTS idx_content_status ON content_items(status);

-- تدريبات 2.0: المراحل الأربع المتفق عليها.
CREATE TABLE IF NOT EXISTS trainings (
  id TEXT PRIMARY KEY,
  content_id TEXT UNIQUE,
  axis_no INTEGER NOT NULL CHECK(axis_no BETWEEN 1 AND 5),
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
  order_index INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(content_id) REFERENCES content_items(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS training_stages (
  id TEXT PRIMARY KEY,
  training_id TEXT NOT NULL,
  stage_no INTEGER NOT NULL CHECK(stage_no BETWEEN 1 AND 4),
  title TEXT NOT NULL,
  instructions TEXT,
  activities_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(training_id,stage_no),
  FOREIGN KEY(training_id) REFERENCES trainings(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_training_stages_training ON training_stages(training_id,stage_no);

-- مهمات التلاميذ والإنتاجات والتصحيح.
CREATE TABLE IF NOT EXISTS missions (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  content_id TEXT,
  title TEXT NOT NULL,
  instructions TEXT NOT NULL,
  due_at TEXT,
  status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','pending','submitted','reviewed','closed')),
  submission_text TEXT,
  submitted_at TEXT,
  feedback TEXT,
  reviewed_at TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY(content_id) REFERENCES content_items(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_missions_student ON missions(student_id,status,created_at);

-- الرسائل المتبادلة بين التلميذ والأستاذ.
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  sender_type TEXT NOT NULL CHECK(sender_type IN ('student','teacher')),
  sender_id TEXT NOT NULL,
  recipient_type TEXT NOT NULL CHECK(recipient_type IN ('student','teacher')),
  recipient_id TEXT NOT NULL,
  body TEXT NOT NULL,
  linked_content_id TEXT,
  linked_mission_id TEXT,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(linked_content_id) REFERENCES content_items(id) ON DELETE SET NULL,
  FOREIGN KEY(linked_mission_id) REFERENCES missions(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_type,recipient_id,is_read,created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_type,sender_id,created_at);

-- الاختبارات التي ينشئها الأستاذ وأسئلة كل اختبار.
CREATE TABLE IF NOT EXISTS tests (
  id TEXT PRIMARY KEY,
  axis_no INTEGER CHECK(axis_no BETWEEN 1 AND 5),
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
  audience TEXT NOT NULL DEFAULT 'assigned' CHECK(audience IN ('public','assigned')),
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS test_questions (
  id TEXT PRIMARY KEY,
  test_id TEXT NOT NULL,
  question_no INTEGER NOT NULL,
  prompt TEXT NOT NULL,
  expected_answer TEXT,
  points REAL NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(test_id,question_no),
  FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS test_assignments (
  id TEXT PRIMARY KEY,
  test_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  assigned_at TEXT NOT NULL,
  FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
  UNIQUE(test_id,student_id)
);
CREATE TABLE IF NOT EXISTS test_answers (
  id TEXT PRIMARY KEY,
  test_id TEXT NOT NULL,
  question_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  answer_text TEXT NOT NULL,
  score REAL,
  feedback TEXT,
  submitted_at TEXT NOT NULL,
  reviewed_at TEXT,
  FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE,
  FOREIGN KEY(question_id) REFERENCES test_questions(id) ON DELETE CASCADE,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
  UNIQUE(test_id,question_id,student_id)
);
CREATE INDEX IF NOT EXISTS idx_test_answers_student ON test_answers(student_id,test_id);

-- ملاحظات الأستاذ وردود التلميذ.
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  note_type TEXT NOT NULL CHECK(note_type IN ('strength','support','next','general')),
  linked_content_id TEXT,
  note_text TEXT NOT NULL,
  student_reply TEXT,
  replied_at TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY(linked_content_id) REFERENCES content_items(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_student ON notes(student_id,created_at);

-- الإعلانات والتنبيهات العامة أو الموجهة.
CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'info',
  linked_content_id TEXT,
  target_student_id TEXT,
  published INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(linked_content_id) REFERENCES content_items(id) ON DELETE SET NULL,
  FOREIGN KEY(target_student_id) REFERENCES students(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_announcements_target ON announcements(target_student_id,published,created_at);

-- الوسائط: روابط خارجية فقط، بلا رفع ملفات.
CREATE TABLE IF NOT EXISTS media_links (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  axis_no INTEGER CHECK(axis_no BETWEEN 1 AND 5),
  description TEXT,
  status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('draft','published','archived')),
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_axis ON media_links(axis_no,status);

-- تتبع تقدم التلميذ في الموارد.
CREATE TABLE IF NOT EXISTS student_progress (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  content_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'started' CHECK(state IN ('started','completed')),
  percent INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY(content_id) REFERENCES content_items(id) ON DELETE CASCADE,
  UNIQUE(student_id,content_id)
);
CREATE INDEX IF NOT EXISTS idx_progress_student ON student_progress(student_id,last_seen_at);

-- سجل النشاطات والأمان.
CREATE TABLE IF NOT EXISTS activity_logs (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL CHECK(actor_type IN ('student','teacher','system')),
  actor_id TEXT,
  action TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info' CHECK(level IN ('info','warning','error')),
  details_json TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_logs(actor_type,actor_id,created_at);
CREATE INDEX IF NOT EXISTS idx_activity_level ON activity_logs(level,created_at);

-- إعدادات المنصة التي يمكن إدارتها من الأستاذ.
CREATE TABLE IF NOT EXISTS platform_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_by TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_training_stages_training ON training_stages(training_id,stage_no);
CREATE INDEX IF NOT EXISTS idx_missions_student ON missions(student_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_type,sender_id,created_at);
CREATE INDEX IF NOT EXISTS idx_test_answers_student ON test_answers(student_id,test_id);
CREATE INDEX IF NOT EXISTS idx_notes_student ON notes(student_id,created_at);
CREATE INDEX IF NOT EXISTS idx_announcements_target ON announcements(target_student_id,published,created_at);
CREATE INDEX IF NOT EXISTS idx_media_axis ON media_links(axis_no,status);
CREATE INDEX IF NOT EXISTS idx_progress_student ON student_progress(student_id,last_seen_at);
CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_logs(actor_type,actor_id,created_at);
CREATE INDEX IF NOT EXISTS idx_activity_level ON activity_logs(level,created_at);
