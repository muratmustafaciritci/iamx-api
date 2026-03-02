import mysql from 'mysql2/promise';
export function makePool(){
  return mysql.createPool({host:process.env.DB_HOST,user:process.env.DB_USER,database:process.env.DB_NAME,password:process.env.DB_PASS,waitForConnections:true,connectionLimit:5,charset:'utf8mb4'});
}
