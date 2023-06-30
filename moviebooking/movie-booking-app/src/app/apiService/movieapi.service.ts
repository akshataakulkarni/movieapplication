import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { MovieData } from '../model/movie-data';
import { TicketData } from '../model/ticket-data';
import { AddmovieData } from '../model/addmovie-data';

@Injectable({
  providedIn: 'root'
})
export class MovieapiService {
  movieServiceUrl = 'http://localhost:8081/api/v1.0/moviebooking';

  constructor(private http:HttpClient) { }

  getAllMovies(token:string){
    let options = {
      headers:{"Authorization":token}
    }
    return this.http.get<MovieData[]>(this.movieServiceUrl+"/getAllMovies",options);
  }

  getMovieById(token:string,movieId:string){
    let options = {
      headers:{"Authorization":token}
    }
    return this.http.get<MovieData>(this.movieServiceUrl+`/movies/search/${movieId}`,options);//fix url here--match api gateway
  }

 
  bookMovie(token:string,movieName:string,moviedata:TicketData){
    let options = {
      headers:{"Authorization":token}
    }
   return this.http.post<any>(this.movieServiceUrl+`/book/${movieName}`,moviedata,options);
  }

  getUserTickets(token:string,userId:string){
    let options = {
      headers:{"Authorization":token}
    }
    return this.http.get<TicketData[]>(this.movieServiceUrl+`/getUserTickets/${userId}`,options);
  }
  
  getAllTickets(token:string){
    let options = {
      headers:{"Authorization":token}
    }
    return this.http.get<TicketData[]>(this.movieServiceUrl+"/getAllTickets",options);
  }

 
  deleteMovie(movieId:string,token:string){
    let options = {
      headers:{"Authorization":token}
    }
    return this.http.delete<any>(this.movieServiceUrl+`/delete/${movieId}`,options);
  }
  
  updateTicketCount(movieName:string,sumTickets:number,token:string){
    let options = {
      headers:{"Authorization":token}
    }

    return this.http.put<any>(this.movieServiceUrl+`/${movieName}/update/${sumTickets}`,movieName,options);
  }
  
  updateMovie(movieName:string,movie:MovieData,token:string){
    let options = {
      headers:{"Authorization":token}
    }
  return this.http.put<any>(this.movieServiceUrl+`/update/${movieName}`,movie,options);
  }

  addMovie(movie:AddmovieData,token:string){
    let options = {
      headers:{"Authorization":token}
    }

    return this.http.post<AddmovieData>(this.movieServiceUrl+"/addmovie",movie,options);
  }

}
