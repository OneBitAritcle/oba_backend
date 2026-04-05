import axios from "axios";

const BASE_URL = "http://onebitearticle.com";

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
});