import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AuthapiService } from './authapi.service';

fdescribe('AuthapiService', () => {
  let service: AuthapiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [AuthapiService]
    });
    service = TestBed.inject(AuthapiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should send a POST request to login user', () => {
    const loginData = { username: 'testuser', password: 'testpassword' };
    service.loginUser(loginData).subscribe();
    const req = httpMock.expectOne(service.authserviceUrl + '/login');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(loginData);

    req.flush({});
  });

  it('should send a POST request to register user', () => {
    const signupData = { username: 'akshatauser', password: 'akshatapassword',email:'akshata@gmail.com',securityQuestion:'colour',securityAnswer:'green' };
    service.registerUser(signupData).subscribe();
    const req = httpMock.expectOne(service.authserviceUrl + '/signup');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(signupData);

    req.flush({});
  });

  it('should send a PATCH request to reset password', () => {
    const resetData = {username:'akshata', email: 'akshata@gmail.com', newPassword: 'newpassword',secQuestion:'colour',secAnswer:'green' };
    service.resetPasswordUser(resetData).subscribe();
    const req = httpMock.expectOne(service.authserviceUrl + '/forgot');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual(resetData);

    req.flush({});
  });
});
