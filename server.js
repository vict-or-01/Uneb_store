const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const http = require("http");
const socketIo = require("socket.io");



const app = express();
const server = http.createServer(app); 
const io = socketIo(server); 
app.use(express.json());
app.use(cors());
const upload = multer({ dest: "uploads/" });

// Configuração do MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "xxxxxxxx", // senha do mysql
  database: "une_store", 
});

// Conecta ao banco de dados
db.connect((err) => {
  if (err) {
    console.error("Erro de conexão com o banco de dados:", err);
    throw err;
  }
  console.log("Conectado ao banco de dados.");
});


// Middleware para autenticar usando JWT
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1]; 
  if (!token) return res.status(401).json({ message: "Acesso negado." });

  jwt.verify(token, "sua_chave_secreta", (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido." });
    req.user = user;
    next();
  });
}

// Rota para cadastro de usuários
app.post("/auth/cadastro", async (req, res) => {
  const { nome, matricula, telefone, senha, tipo_usuario, curso, funcao, departamento } = req.body;

  if (!nome || !matricula || !telefone || !senha || !tipo_usuario) {
    return res.status(400).json({ message: "Preencha todos os campos obrigatórios!" });
  }

  try {
    const hashedPassword = await bcrypt.hash(senha, 10);

    db.query(
      "INSERT INTO users SET ?",
      { nome, matricula, telefone, senha: hashedPassword, tipo_usuario, curso, funcao, departamento },
      (err) => {
        if (err) {
          console.error("Erro ao cadastrar usuário:", err);
          return res.status(400).json({ message: "Erro ao cadastrar usuário." });
        }
        res.status(201).json({ message: "Usuário cadastrado com sucesso!" });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});

// Configurações e rotas do servidor (mantenha o restante do código aqui)
io.on("connection", (socket) => {
  console.log("Usuário conectado:", socket.id);

  // Gerencie o envio de mensagens
  socket.on("chat_message", (data) => {
      
      io.to(data.to).emit("chat_message", {
          message: data.message,
          from: data.from,
      });
  });

  // Armazena o ID do socket para identificar usuários
  socket.on("register", (userId) => {
      socket.join(userId);
      console.log(`Usuário ${userId} registrado no socket ${socket.id}`);
  });

  socket.on("disconnect", () => {
      console.log("Usuário desconectado:", socket.id);
  });
});


// Rota para login de usuários
app.post("/auth/login", (req, res) => {
  const { matricula, senha } = req.body;

  db.query("SELECT * FROM users WHERE matricula = ?", [matricula], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: "Usuário não encontrado." });

    const user = results[0];
    if (!(await bcrypt.compare(senha, user.senha))) {
      return res.status(400).json({ message: "Senha incorreta." });
    }

    const token = jwt.sign({ id: user.id, matricula: user.matricula }, "sua_chave_secreta");
    res.json({ token });
  });
});

// Rota para adicionar produtos
app.post("/produtos/adicionar", authenticateToken, upload.array("fotos"), (req, res) => {
  const { nome, categoria, condicao, descricao, preco } = req.body;
  const user_id = req.user.id;
  const imagens = req.files.map((file) => file.path).join(",");

  db.query(
    "INSERT INTO products SET ?",
    { user_id, nome, categoria, condicao, descricao, preco, imagens },
    (err) => {
      if (err) return res.status(400).json({ message: "Erro ao adicionar produto." });
      res.json({ message: "Produto adicionado com sucesso!" });
    }
  );
});

// Rota para listar todos os produtos, excluindo os do usuário logado
app.get("/produtos/todos", authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT 
      p.*, 
      u.departamento,
      COALESCE(l.likes, 0) AS total_likes,
      COALESCE(d.dislikes, 0) AS total_dislikes
    FROM products p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN (
      SELECT product_id, COUNT(*) AS likes
      FROM likes
      WHERE type = 'like'
      GROUP BY product_id
    ) l ON p.id = l.product_id
    LEFT JOIN (
      SELECT product_id, COUNT(*) AS dislikes
      FROM likes
      WHERE type = 'dislike'
      GROUP BY product_id
    ) d ON p.id = d.product_id
    WHERE p.user_id != ?; -- Exclui os produtos do usuário logado
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Erro ao buscar produtos:", err);
      return res.status(500).json({ message: "Erro ao buscar produtos." });
    }

    const produtosCorrigidos = results.map((produto) => ({
      ...produto,
      primeiraFoto: produto.imagens ? produto.imagens.split(",")[0] : "imagens/default.jpg",
    }));

    res.json(produtosCorrigidos);
  });
});


// Rota para listar os anúncios do usuário logado
app.get("/usuario/meus-anuncios", authenticateToken, (req, res) => {
  const user_id = req.user.id; 

  if (!user_id) {
    return res.status(400).json({ message: "Usuário não autenticado." });
  }


  const query = "SELECT * FROM products WHERE user_id = ?";
  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error("Erro ao buscar anúncios do usuário:", err);
      return res.status(500).json({ message: "Erro ao buscar anúncios." });
    }

    res.json(results);
  });
});

// Rota para excluir um produto
app.delete("/produtos/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const user_id = req.user.id;

 
  db.query("DELETE FROM products WHERE id = ? AND user_id = ?", [id, user_id], (err, results) => {
    if (err) {
      console.error("Erro ao excluir produto:", err);
      return res.status(500).json({ message: "Erro ao excluir o produto." });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Produto não encontrado ou não autorizado." });
    }

    res.json({ message: "Produto excluído com sucesso!" });
  });
});


// Rota para listar mensagens do chat
app.get("/chat/mensagens/:vendedorId", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const vendedorId = req.params.vendedorId;

  const query = `
    SELECT m.*, u.nome AS sender_nome
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.created_at ASC
  `;

  db.query(query, [userId, vendedorId, vendedorId, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Erro ao carregar mensagens." });
    }
    res.json(results);
  });
});


// Rota para enviar mensagem
app.post("/chat/enviar", authenticateToken, (req, res) => {
  const { receiverId, message } = req.body;
  const senderId = req.user.id;

  db.query(
    "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
    [senderId, receiverId, message],
    (err) => {
      if (err) {
        return res.status(500).json({ message: "Erro ao enviar mensagem." });
      }
      res.json({ message: "Mensagem enviada com sucesso!" });
    }
  );
});

// Rota para atualizar informações do perfil
app.put("/usuario/atualizar", authenticateToken, upload.single("foto"), (req, res) => {
  const { nome, telefone, senha } = req.body;
  const userId = req.user.id;
  const novaFoto = req.file ? req.file.path : null;

  const camposAtualizados = { nome, telefone };
  if (senha) {
    camposAtualizados.senha = bcrypt.hashSync(senha, 10);
  }
  if (novaFoto) {
    camposAtualizados.foto = novaFoto;
  }

  db.query(
    "UPDATE users SET ? WHERE id = ?",
    [camposAtualizados, userId],
    (err, result) => {
      if (err) return res.status(500).json({ message: "Erro ao atualizar perfil." });
      res.json({ message: "Perfil atualizado com sucesso!" });
    }
  );
});



// Rota para obter informações do perfil do usuário logado
app.get("/usuario/perfil", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query(
    "SELECT id, nome, matricula, telefone, foto FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ message: "Perfil não encontrado." });
      }
      res.json(results[0]);
    }
  );
});


// Rota para editar um produto pelo ID
app.put("/produtos/:id", authenticateToken, upload.array("fotos"), (req, res) => {
  const { id } = req.params; // ID do produto
  const { nome, categoria, condicao, descricao, preco } = req.body;
  const user_id = req.user.id; // ID do usuário autenticado

  
  const imagens = req.files?.map((file) => file.path).join(",") || null;

 
  const query = `
    UPDATE products 
    SET nome = ?, categoria = ?, condicao = ?, descricao = ?, preco = ?, imagens = COALESCE(?, imagens)
    WHERE id = ? AND user_id = ?
  `;

  db.query(
    query,
    [nome, categoria, condicao, descricao, preco, imagens, id, user_id],
    (err, result) => {
      if (err) {
        console.error("Erro ao atualizar produto:", err);
        return res.status(500).json({ message: "Erro ao atualizar o produto." });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Produto não encontrado ou não autorizado." });
      }

      res.json({ message: "Produto atualizado com sucesso!" });
    }
  );
});

// Rota para registrar reação (like ou dislike)
app.post("/likes", (req, res) => {
  const { userId, productId, type } = req.body;

  const queryCheck = `
    SELECT * FROM likes WHERE user_id = ? AND product_id = ?`;
  const queryInsert = `
    INSERT INTO likes (user_id, product_id, type) VALUES (?, ?, ?)`;
  const queryUpdate = `
    UPDATE likes SET type = ? WHERE user_id = ? AND product_id = ?`;

  db.query(queryCheck, [userId, productId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length > 0) {
      
      db.query(queryUpdate, [type, userId, productId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Reação atualizada com sucesso" });
      });
    } else {
     
      db.query(queryInsert, [userId, productId, type], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Reação registrada com sucesso" });
      });
    }
  });
});

// Rota para obter contagem de likes e dislikes por produto
app.get("/likes/:productId", (req, res) => {
  const { productId } = req.params;

  const queryLikes = `
    SELECT COUNT(*) AS total FROM likes WHERE product_id = ? AND type = 'like'`;
  const queryDislikes = `
    SELECT COUNT(*) AS total FROM likes WHERE product_id = ? AND type = 'dislike'`;

  db.query(queryLikes, [productId], (err, likes) => {
    if (err) return res.status(500).json({ error: err.message });

    db.query(queryDislikes, [productId], (err, dislikes) => {
      if (err) return res.status(500).json({ error: err.message });

      res.status(200).json({
        likes: likes[0].total,
        dislikes: dislikes[0].total,
      });
    });
  });
});


// Rota para filtrar produtos por departamento do vendedor
app.get("/produtos/filtrar", authenticateToken, (req, res) => {
  const userId = req.user.id; // ID do usuário logado
  const departamento = req.query.departamento; // Parâmetro enviado pela query

  if (!departamento) {
    return res.status(400).json({ message: "Departamento não fornecido." });
  }


  let query = `
    SELECT p.*, u.departamento
    FROM products p
    JOIN users u ON p.user_id = u.id
    WHERE p.user_id != ? -- Exclui os produtos do usuário logado
  `;

  const params = [userId];

  
  if (departamento !== "TODOS") {
    if (departamento === "FUNCIONARIO") {
      query += " AND u.tipo_usuario = 'funcionario'";
    } else {
      query += " AND u.departamento = ?";
      params.push(departamento);
    }
  }

  db.query(query, params, (err, results) => {
    if (err) {
      console.error("Erro ao buscar produtos:", err);
      return res.status(500).json({ message: "Erro ao buscar produtos." });
    }

   
    const produtosCorrigidos = results.map((produto) => ({
      ...produto,
      primeiraFoto: produto.imagens ? produto.imagens.split(",")[0] : "imagens/default.jpg",
    }));

    res.json(produtosCorrigidos);
  });
});

// Rota para filtrar produtos por categoria
app.get("/produtos/filtrarPorCategoria", authenticateToken, (req, res) => {
  const userId = req.user.id; // ID do usuário logado
  const categoria = req.query.categoria; // Categoria enviada pela query

  
  if (!categoria) {
    return res.status(400).json({ message: "Categoria não fornecida." });
  }

  
  let query = `
    SELECT p.*, u.nome AS vendedor
    FROM products p
    JOIN users u ON p.user_id = u.id
    WHERE p.user_id != ? -- Exclui os produtos do usuário logado
  `;
  const params = [userId];

  
  if (categoria !== "todos") {
    query += " AND p.categoria = ?";
    params.push(categoria);
  }

  db.query(query, params, (err, results) => {
    if (err) {
      console.error("Erro ao buscar produtos por categoria:", err);
      return res.status(500).json({ message: "Erro ao buscar produtos." });
    }

   
    const produtosCorrigidos = results.map((produto) => ({
      ...produto,
      primeiraFoto: produto.imagens ? produto.imagens.split(",")[0] : "imagens/default.jpg",
    }));

    res.json(produtosCorrigidos);
  });
});


// Rota para buscar produtos por nome
app.get("/produtos/buscar", authenticateToken, (req, res) => {
  const userId = req.user.id; 
  const termo = req.query.nome;

  if (!termo) {
    return res.status(400).json({ message: "Termo de busca não fornecido." });
  }

  const query = `
    SELECT p.*, u.departamento 
    FROM products p 
    JOIN users u ON p.user_id = u.id 
    WHERE p.user_id != ? AND p.nome LIKE ? 
  `;
  const params = [userId, `%${termo}%`];

  db.query(query, params, (err, results) => {
    if (err) {
      console.error("Erro ao buscar produtos:", err);
      return res.status(500).json({ message: "Erro ao buscar produtos." });
    }

    const produtosCorrigidos = results.map((produto) => ({
      ...produto,
      primeiraFoto: produto.imagens ? produto.imagens.split(",")[0] : "imagens/default.jpg",
    }));

    res.json(produtosCorrigidos);
  });
});

// Rota para buscar um produto pelo ID
app.get("/produtos/:id", authenticateToken, (req, res) => {
  const { id } = req.params;

  db.query("SELECT * FROM products WHERE id = ?", [id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: "Produto não encontrado." });
    res.json(results[0]);
  });
});

// Rota para buscar informações do vendedor
app.get("/chat/vendedor/:vendedorId", authenticateToken, (req, res) => {
  const vendedorId = req.params.vendedorId;

  db.query("SELECT nome, foto FROM users WHERE id = ?", [vendedorId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: "Vendedor não encontrado." });
    }
    res.json(results[0]);
  });
});



//Rota para listar usuários e contagem de produtos

app.get('/api/usuarios', (req, res) => {
  const query = `
    SELECT u.id, u.nome, u.telefone, u.curso, u.departamento, u.foto,
           COUNT(p.id) AS produtos_anunciados,
           GROUP_CONCAT(DISTINCT p.categoria SEPARATOR ', ') AS categorias
    FROM users u
    LEFT JOIN products p ON u.id = p.user_id
    GROUP BY u.id, u.nome, u.telefone, u.curso, u.departamento, u.foto
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Erro ao buscar usuários:", err);
      return res.status(500).json({ message: "Erro ao buscar usuários." });
    }
    res.json(results);
  });
});

// rotas para chat
app.get("/chats/todos", authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT 
      c.id AS chatId,
      c.mensagem AS ultimaMensagem,
      u.nome AS outroUsuario,
      u.foto AS fotoUsuario,
      p.nome AS produto
    FROM chats c
    LEFT JOIN users u 
      ON (u.id = c.buyer_id AND c.seller_id = ?) 
      OR (u.id = c.seller_id AND c.buyer_id = ?)
    LEFT JOIN products p 
      ON c.product_id = p.id
    WHERE c.buyer_id = ? OR c.seller_id = ?
    ORDER BY c.data_envio DESC;
  `;

  db.query(query, [userId, userId, userId, userId], (err, results) => {
    if (err) {
      console.error("Erro ao buscar chats:", err);
      return res.status(500).json({ message: "Erro ao buscar chats." });
    }

    res.json(results);
  });
});


  

// Rota para listar usuários com produtos anunciados e mensagens com o usuário logado
app.get("/chats/usuarios-e-produtos", authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT DISTINCT 
      u.id AS usuarioId,
      u.nome AS usuarioNome,
      u.foto AS usuarioFoto,
      COUNT(p.id) AS produtosAnunciados,
      GROUP_CONCAT(DISTINCT p.nome SEPARATOR ', ') AS produtos
    FROM messages m
    JOIN users u ON u.id = CASE
        WHEN m.sender_id = ? THEN m.receiver_id
        WHEN m.receiver_id = ? THEN m.sender_id
      END
    LEFT JOIN products p ON p.user_id = u.id
    WHERE m.sender_id = ? OR m.receiver_id = ?
    GROUP BY u.id;
  `;

  db.query(query, [userId, userId, userId, userId], (err, results) => {
    if (err) {
      console.error("Erro ao buscar dados:", err);
      return res.status(500).json({ message: "Erro ao buscar dados." });
    }
    res.json(results);
  });
});





// Inicialização do servidor
app.listen(3000, () => {
  console.log("Servidor rodando na porta 3000");
});
