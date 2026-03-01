import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ScholarsComponent } from './scholars-component';

describe('ScholarsComponent', () => {
  let component: ScholarsComponent;
  let fixture: ComponentFixture<ScholarsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ScholarsComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ScholarsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
