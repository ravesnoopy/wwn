# Publicar en GitHub
1. Crea en GitHub un repositorio vacío llamado `WhiteWidow-net` (sin README ni .gitignore).
2. Extrae el ZIP y entra a la carpeta:
```bash
unzip WhiteWidowNet_Full_Project_v1.1.0.zip && cd whitewidow-net
git init -b main && git add . && git commit -m "feat: WhiteWidow Net v1.1.0"
git remote add origin https://github.com/ravesnoopy/WhiteWidow-net.git
git push -u origin main
```
3. Release con paquete .deb: `git tag v1.1.0 && git push origin v1.1.0` (el workflow `release.yml` ejecuta pruebas, construye el .deb y lo adjunta).
4. Antes de publicar: nada en el repo contiene tokens; `config.json` y `*.db` están en `.gitignore`. Nota: existen otros proyectos llamados "WhiteWidow"; revisa que el nombre te sirva.
