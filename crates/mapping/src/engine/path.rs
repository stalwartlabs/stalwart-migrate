#[derive(Debug, Default)]
pub(crate) struct Path {
    text: String,
    marks: Vec<usize>,
}

impl Path {
    pub fn push(&mut self, segment: &str) {
        self.marks.push(self.text.len());
        if !self.text.is_empty() {
            self.text.push('/');
        }
        self.text.push_str(segment);
    }

    pub fn pop(&mut self) {
        if let Some(mark) = self.marks.pop() {
            self.text.truncate(mark);
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn child(&self, segment: &str) -> String {
        if self.text.is_empty() {
            segment.to_string()
        } else {
            format!("{}/{segment}", self.text)
        }
    }
}
