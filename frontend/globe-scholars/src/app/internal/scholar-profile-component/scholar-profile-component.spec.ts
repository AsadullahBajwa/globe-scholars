import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ScholarProfileComponent } from './scholar-profile-component';

describe('ScholarProfileComponent', () => {
  let component: ScholarProfileComponent;
  let fixture: ComponentFixture<ScholarProfileComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ScholarProfileComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ScholarProfileComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
