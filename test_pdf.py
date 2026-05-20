from fpdf import FPDF

class Test(FPDF):
    def section_title(self, title):
        self.ln(5)
        self.set_font('Helvetica', 'B', 13)
        self.set_fill_color(31, 56, 100)
        self.set_text_color(255, 255, 255)
        self.cell(0, 9, f'  {title}', fill=True, ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

pdf = Test()
pdf.add_page()
pdf.set_font('Helvetica', '', 10)
pdf.section_title('Test Section')
pdf.set_font('Helvetica', '', 10)
print('x before multi_cell:', pdf.get_x())
print('w:', pdf.w, 'r_margin:', pdf.r_margin)
print('usable:', pdf.w - pdf.get_x() - pdf.r_margin)
pdf.multi_cell(0, 6, '- Test system (192.168.1.10)')
print('Success!')
