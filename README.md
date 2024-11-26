# Proyecto Final de Criptografía: Implementación de AES-GCM para IoT

Este proyecto implementa el algoritmo de cifrado AES-GCM, cumpliendo con los estándares del **NIST SP 800-38D**, para asegurar la comunicación en dispositivos IoT. Se enfoca en la autenticación de datos y el cifrado eficiente, considerando las limitaciones de hardware y recursos de estos dispositivos.

---

analisis del algoritmo gcm, como funciona, por que es bueno, 

metricas

   - tamaño de clave    
   - tiempo
   - gasto energetico

contexto, por que es bueno, era cuantica?


## **Introducción**

### **Motivación**
Los dispositivos IoT presentan desafíos únicos para la implementación de seguridad, como limitaciones de potencia y capacidad de procesamiento. Este proyecto:
- Utiliza el algoritmo **AES-GCM**, recomendado por NIST para comunicaciones seguras.
- Implementa una **Derivación de Claves con HKDF**, para mejorar la seguridad al generar claves únicas.
- Prueba el algoritmo en escenarios reales simulados con diferentes tamaños de datos (1 KB, 10 KB, 100 KB), midiendo tiempos de cifrado y descifrado.

### **Objetivo**
Demostrar que el cifrado AES-GCM es una solución eficiente y segura para la comunicación de dispositivos IoT, cumpliendo con los estándares internacionales y proporcionando resultados medibles.

---

## **Características del Proyecto**

### **Innovación**
- **Aplicación en IoT**: El algoritmo AES-GCM se adapta a un entorno de recursos limitados.
- **Seguridad Mejorada**: Derivación de claves con HKDF para evitar el uso de claves débiles o predecibles.
- **Logs y Auditoría**: Uso de logs detallados para garantizar la trazabilidad y verificar el cumplimiento normativo.

### **Implementación**
- Lenguaje: **Rust**, por su eficiencia y seguridad en el manejo de memoria.
- Algoritmos:
  - **AES-GCM**: Para cifrado autenticado.
  - **HKDF**: Derivación de claves basada en SHA-256.

### **Pruebas**
- Tamaños de texto plano: 1 KB, 10 KB y 100 KB.
- Métricas evaluadas:
  - Tiempo de cifrado.
  - Tiempo de descifrado.
  - Verificación de integridad de datos descifrados.

---

## **Instrucciones de Ejecución**

### **Requisitos**
1. **Rust** instalado en el sistema.
2. Dependencias del proyecto:
   - `log`
   - `env_logger`
   - `aes-gcm`
   - `hkdf`
   - `sha2`
   - `rand`

### **Instalación**
1. Clona este repositorio:
   ```bash
   git clone <url_del_repositorio>
   cd aes_gcm_iot
   ```
2. Instala las dependencias:
   ```bash
   cargo build
   ```

### **Ejecución**
1. Ejecuta el programa con los logs habilitados:
   ```bash
   RUST_LOG=info cargo run
   ```

2. **Salida esperada**:
   El programa imprimirá los resultados detallados para cada prueba, incluyendo:
   - Tamaño de los datos procesados.
   - Tiempo de cifrado y descifrado.
   - Validación de la integridad del texto descifrado.

---

## **Resultados**

### **Datos de Ejemplo**
#### Entrada:
- Clave maestra: Generada aleatoriamente (32 bytes).
- Salt: Generado aleatoriamente (16 bytes).
- Datos asociados: `"datos asociados"`.

#### Salida:
```plaintext
INFO: Clave maestra y salt generados correctamente.
INFO: Clave derivada correctamente: [34, 123, 255, ...].
INFO: Iniciando pruebas con tamaño de texto plano: 1024 bytes.
INFO: Cifrado completado en 1.23ms. Nonce utilizado: [45, 89, 123, ...].
INFO: Descifrado completado en 1.12ms. Primeros 32 bytes del descifrado: [0, 0, 0, 0, ...].
INFO: Validación exitosa: El texto descifrado coincide con el original.
--------------------------------------------
INFO: Iniciando pruebas con tamaño de texto plano: 10240 bytes.
INFO: Cifrado completado en 2.45ms. Nonce utilizado: [34, 99, 12, ...].
INFO: Descifrado completado en 2.33ms. Primeros 32 bytes del descifrado: [0, 0, 0, 0, ...].
INFO: Validación exitosa: El texto descifrado coincide con el original.
--------------------------------------------
INFO: Iniciando pruebas con tamaño de texto plano: 102400 bytes.
INFO: Cifrado completado en 12.56ms. Nonce utilizado: [12, 45, 78, ...].
INFO: Descifrado completado en 12.02ms. Primeros 32 bytes del descifrado: [0, 0, 0, 0, ...].
INFO: Validación exitosa: El texto descifrado coincide con el original.
--------------------------------------------
```

### **Resultados de Rendimiento**

| **Tamaño de Datos** | **Tiempo de Cifrado (ms)** | **Tiempo de Descifrado (ms)** |
|----------------------|----------------------------|--------------------------------|
| 1 KB                | 1.23                       | 1.12                           |
| 10 KB               | 2.45                       | 2.33                           |
| 100 KB              | 12.56                      | 12.02                          |

---

## **Conclusiones**

1. **Eficiencia y Escalabilidad**:
   - Los tiempos de cifrado y descifrado son adecuados para aplicaciones IoT.
   - El algoritmo escala bien con el tamaño de los datos.

2. **Cumplimiento Normativo**:
   - Cada operación utiliza un **nonce único**.
   - Los datos asociados son autenticados para garantizar la integridad.

3. **Aplicabilidad**:
   - Esta implementación puede integrarse en sistemas IoT para proteger la comunicación entre dispositivos.

---
