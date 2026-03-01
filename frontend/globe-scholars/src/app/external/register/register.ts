import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from "@angular/router";
import { AuthService } from '../../services/auth/auth-service';
import { NewUser, UserAccount } from '../../services/auth/interface';

@Component({
selector: 'app-register',
imports: [RouterLink, ReactiveFormsModule],
templateUrl: './register.html',
styleUrl: './register.scss',
})
export class Register implements OnInit {
constructor(
  private authService: AuthService,
){}

apiErrorMsg:string = ''
formErrorMsg:string = ''

form = new FormGroup({
  first_name: new FormControl('', [Validators.required, Validators.minLength(2)]),
  last_name: new FormControl('', [Validators.required, Validators.minLength(2)]),
  username: new FormControl('', [Validators.required, Validators.minLength(2)]),
  password: new FormControl('', [Validators.required, Validators.pattern(/^(?=\S*?[A-Z])(?=\S*?[a-z])(?=\S*?[0-9])\S{6,}$/)]),//min 6 chars, at least 1 uppercase, at least 1 lowercase, at least 1 number, no spaces
  password2: new FormControl('', [Validators.required])
})

ngOnInit(): void {}

validateForm() {
  if(this.firstName?.invalid || this.lastName?.invalid || this.username?.invalid || this.password?.invalid || this.password2?.invalid){
    this.formErrorMsg = "Please fill in all the fields!";
    return false;
  }
  this.formErrorMsg = '';
  return true;
}

async register() {
  if (!this.validateForm()) return;
  const values = this.form.getRawValue();
  const params:NewUser = {
    first_name: values.first_name,
    last_name: values.last_name,
    username: values.username,
    password: values.password,
    password2: values.password2
}
this.authService.register(params).subscribe({
  next: (res: UserAccount) => {
  console.log(res.message)
  this.form.reset();
},
  error: (res) => {
    if (res.error.username) {
      this.username?.setErrors({ error: res.error.username[0] });
    }
    if (res.error.password) {
      this.password?.setErrors({ error: res.error.password[0] });
    }
    this.form.markAllAsTouched();
  console.log(res.error)
  }
  });
}

// getters for form values
  get firstName() {
    return this.form.get('first_name')
  }
  get lastName() {
    return this.form.get('last_name')
  }
  get username() {
    return this.form.get('username')
  }
  get password() {
    return this.form.get('password')
  }
  get password2() {
    return this.form.get('password2')
  }
}