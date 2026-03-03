import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Register } from './register';
import { AuthService } from '../../services/auth/auth-service';
import { NewUser } from '../../services/auth/interface';

describe('Register', () => {
  let component: Register;
  let fixture: ComponentFixture<Register>;
  let authService: AuthService;

  const newUser: NewUser = {
    first_name: 'John',
    last_name: 'Doe',
    username: 'johnD',
    password: 'Password123',
    password2: 'Password123'
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Register]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Register);
    component = fixture.componentInstance;
    authService = TestBed.inject(AuthService);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  //test if the form is created with the needed form controls
  it('should create a form group with controls', () => {
      expect(component.form).toBeDefined();
      expect(component.form.get('first_name')).toBeDefined();
      expect(component.form.get('last_name')).toBeDefined();
      expect(component.form.get('username')).toBeDefined();
      expect(component.form.get('password')).toBeDefined();
      expect(component.form.get('password2')).toBeDefined();
  });

  // test that if either of the fields are invalid, an error message is passed to the formErrorMsg variable
  it('should validate form and show error when invalid', () => {
    component.validateForm();
    expect(component.formErrorMsg).toBe('Please fill in all the fields!');
  });

  //test that if the form is invalid it does not call the register method
  it('should not call the register method if the form is invalid', () => {
    spyOn(authService, 'register');
    component.register();
    expect(authService.register).not.toHaveBeenCalled();
  })

  // test that the values entered by the user in the form is captured in the params object
  it('should capture form values in params object', () => {
    component.form.patchValue(newUser);
    
    const params = component.form.getRawValue();
    expect(params.first_name).toBe(newUser.first_name);
    expect(params.last_name).toBe(newUser.last_name);
    expect(params.username).toBe(newUser.username);
    expect(params.password).toBe(newUser.password);
    expect(params.password2).toBe(newUser.password2);
  });

  // test that the register method of the authService receives the params
  it('should pass params to authService.register', () => {
    spyOn(authService, 'register');
    component.form.patchValue(newUser);
    component.register();
    expect(authService.register).toHaveBeenCalledWith(jasmine.any(Object));
  });

  //test that the inputs show the user an error if its touched or dirty

  //test the password pattern
  it('should validate password pattern', () => {
    component.password?.setValue('hello');
    expect(component.password?.hasError('pattern')).toBeTrue();
    component.password?.setValue('Password123');
    expect(component.password?.hasError('pattern')).toBeFalse();
  });
});
