import {Component} from '@angular/core';
import {ReactiveFormsModule, FormGroup, FormBuilder, FormArray, Validators} from '@angular/forms';
import {RouterModule} from '@angular/router';

@Component({
  selector: 'app-upload-work-component',
  imports: [ReactiveFormsModule, RouterModule],
  templateUrl: './upload-work-component.html',
  styleUrl: './upload-work-component.scss',
})
export class UploadWorkComponent {
  uploadForm: FormGroup;
  submitted = false;
  selectedFile: File | null = null;
  fileError: string = '';

  constructor(private fb: FormBuilder) {
    this.uploadForm = this.fb.group({
      title: ['', Validators.required],
      authors: this.fb.array([
        this.fb.control('', Validators.required)
      ]),
      publicationDate: ['', Validators.required],
      description: ['']
    });
  }

  get authors(): FormArray {
    return this.uploadForm.get('authors') as FormArray;
  }

  addAuthor() {
    this.authors.push(this.fb.control('', Validators.required));
  }

  removeAuthor(index: number) {
    if (this.authors.length > 1) {
      this.authors.removeAt(index);
    }
  }

  onFileChange(event: any) {
    const file = event.target.files[0];
    if (!file) return;

    const allowedTypes = [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];

    if (!allowedTypes.includes(file.type)) {
      this.fileError = 'Only .pdf and .docx files are allowed';
      this.selectedFile = null;
    } else {
      this.fileError = '';
      this.selectedFile = file;
    }
  }

  onSubmit() {
    this.submitted = true;

    if (this.uploadForm.invalid || !this.selectedFile) {
      if (!this.selectedFile) {
        this.fileError = 'File is required';
      }
      return;
    }

    console.log('Form Data:', this.uploadForm.value);
    console.log('Selected File:', this.selectedFile);

    // TODO: Implement actual upload logic here (send data to backend)

    this.uploadForm.reset();
    this.authors.clear();
    this.addAuthor();
    this.selectedFile = null;
    this.submitted = false;
  }

  isFieldInvalid(field: string): boolean {
    const control = this.uploadForm.get(field);
    return !!(control && control.invalid && (control.dirty || control.touched || this.submitted));
  }

  isAuthorInvalid(index: number): boolean {
    const control = this.authors.at(index);
    return (control && control.invalid && (control.dirty || control.touched || this.submitted));
  }
}
