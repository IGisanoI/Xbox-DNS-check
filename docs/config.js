/*
 * Конфигурация облачной отправки веб-версии.
 * ВНИМАНИЕ: этот файл публичен (статический сайт). Токен виден любому,
 * кто откроет исходник страницы. Для пилота осознанно принято
 * (см. cloud/TOKEN-ROTATION.md — процедура ротации токена).
 * Десктопная программа использует тот же INGEST_TOKEN из своего cloud_config.json.
 */
window.DNSCHECK_CONFIG = {
  endpoint: "https://script.google.com/macros/s/AKfycbwYpDCQIzKIKbwAr9YT-t4vGaWw8aXwFrWBq8Ml905eDNXGWXDNjvEssVjUcFHChLwf/exec",
  token: "X9zk_9jhY1ma1ACX88TL53Ly5O8mzKT6REypuwsFf_DEGcHR",
  appVersion: "web-1.0",
};
