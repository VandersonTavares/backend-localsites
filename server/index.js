import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCors from "@fastify/cors";
import fastifyMultipart from "@fastify/multipart";
import { WebSocketServer } from 'ws';
import { pipeline } from "stream";
import { promisify } from "util";
const pump = promisify(pipeline);

import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import path from "path";
import fs from "fs";

import { PrismaClient, Role } from "@prisma/client";

dotenv.config();

const app = Fastify({ logger: true });
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "secret-key";

// Função para criar usuário admin padrão
async function createDefaultAdmin() {
  try {
    const existingAdmin = await prisma.user.findFirst({
      where: { username: "adminroot" }
    });
    
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash("adminroot", 10);
      await prisma.user.create({
        data: {
          username: "adminroot",
          password: hashedPassword,
          role: Role.admin,
          isRoot: true
        }
      });
      console.log("✅ Usuário adminroot criado com sucesso");
    } else {
      console.log("ℹ️  Usuário adminroot já existe");
    }
  } catch (error) {
    console.error("❌ Erro ao criar usuário admin:", error);
  }
}

// CORS
// Registra o CORS com origem liberada para o frontend Vite
app.register(fastifyCors, {
  origin: ["http://localhost:5173", "https://mediumblue-bear-363121.hostingersite.com"], // ou '*' para liberar geral (não recomendado em prod)
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
});

// guarda as conexões WebSocket ativas
const wsClients = new Set();

// função para enviar dados para todos os clientes conectados
function broadcast(data) {
  const message = JSON.stringify(data);
  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  }
}

// Configuração do Prisma
app.register(fastifyMultipart);

// Parse JSON (Fastify já faz parse automático para JSON em body)
// Serve arquivos estáticos (uploads)
app.register(fastifyStatic, {
  root: path.join(process.cwd(), "uploads"),
  prefix: "/uploads/",
});

// Middleware de autenticação adaptado para Fastify
async function authenticate(request, reply) {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      return reply.status(401).send({ message: "Token não fornecido" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    request.user = decoded;
  } catch (err) {
    return reply.status(403).send({ message: "Token inválido" });
  }
}

// Adaptar middleware para Fastify
app.decorate("authenticate", authenticate);

// rota de upload de imagem
app.post("/api/upload", async (request, reply) => {
  const data = await request.file();

  if (!data || !data.filename) {
    return reply.status(400).send({ message: "Arquivo não enviado" });
  }

  const ext = path.extname(data.filename);
  const baseName = path
    .basename(data.filename, ext)
    .replace(/\s+/g, "-")
    .toLowerCase();
  const fileName = `${baseName}-${Date.now()}${ext}`;
  const filePath = path.join("uploads", fileName);

  await pump(data.file, fs.createWriteStream(filePath));

  reply.send({ url: `/uploads/${fileName}` });
});

// garante que a pasta uploads existe
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

//rota de upload de logo
app.post("/api/upload-logo", async (request, reply) => {
  const data = await request.file();

  if (!data || !data.filename) {
    return reply.status(400).send({ message: "Arquivo não enviado" });
  }

  const ext = path.extname(data.filename);
  const baseName = path
    .basename(data.filename, ext)
    .replace(/\s+/g, "-")
    .toLowerCase();
  const fileName = `${baseName}-${Date.now()}${ext}`;
  const filePath = path.join(uploadDir, fileName);

  await pump(data.file, fs.createWriteStream(filePath));

  reply.send({ url: `/uploads/${fileName}` });
});

// --- Rotas ---
// Todas rotas protegidas usam onRequest hook com authenticate
app.post("/api/admin/validate-password", async (request, reply) => {
  try {
    const { password } = request.body;

    if (!password) {
      return reply.status(400).send({ message: "Senha é obrigatória" });
    }

    // Busca o usuário root no banco (supondo que isRoot=true identifica o admin principal)
    const adminUser = await prisma.user.findFirst({
      where: { isRoot: true },
    });

    if (!adminUser) {
      return reply
        .status(404)
        .send({ message: "Usuário admin não encontrado" });
    }

    // Compara a senha informada com o hash salvo no banco
    const isValid = await bcrypt.compare(password, adminUser.password);

    if (!isValid) {
      return reply.status(401).send({ message: "Senha inválida" });
    }

    // Senha válida
    return reply.send({ message: "Senha válida" });
  } catch (error) {
    app.log.error(error);
    return reply.status(500).send({ message: "Erro interno" });
  }
});

// Rota para listar lojas
// (para administradores)
// Esta rota é usada para exibir todas as lojas cadastradas
app.get(
  "/api/stores",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const user = request.user;
    if (user.role !== Role.admin) {
      return reply.status(403).send({
        message: "Acesso negado: apenas administradores",
      });
    }

    try {
      const stores = await prisma.store.findMany({
        include: { user: { select: { username: true } } },
      });
      reply.send(stores);
    } catch (error) {
      app.log.error(error);
      reply.status(500).send({ message: "Erro ao buscar lojas" });
    }
  }
);

// Rota para login
// Esta rota é usada para autenticar usuários e gerar tokens JWT
// Ela recebe o nome de usuário e senha, valida as credenciais e retorna um token JWT
app.post("/api/auth/login", async (request, reply) => {
  const { username, password } = request.body;
  const user = await prisma.user.findUnique({
    where: { username },
    include: { store: true },
  });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return reply.status(401).send({ message: "Credenciais inválidas" });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1h",
  });
  reply.send({
    token,
    user: { username: user.username, storeSlug: user.store?.slug },
  });
});

// Rota para listar usuários
// (para administradores)
// Esta rota é usada para exibir todos os usuários cadastrados
// Apenas administradores podem acessar esta rota
app.get(
  "/api/users",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const user = request.user;
    if (user.role !== Role.admin) {
      return reply.status(403).send({ message: "Acesso negado" });
    }
    try {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          username: true,
          role: true,
          isRoot: true,
          store: true,
        },
      });

      const sanitizedUsers = users.map((u) => {
        const sanitized = {
          id: u.id,
          username: u.username,
          role: u.role,
        };
        if (u.role === Role.admin) {
          sanitized.isRoot = u.isRoot;
        } else {
          sanitized.store = u.store;
        }
        return sanitized;
      });

      reply.send(sanitizedUsers);
    } catch (error) {
      reply.status(500).send({ message: "Erro ao buscar usuários" });
    }
  }
);

// Rota para criar usuário cliente e loja
// (para lojas)
app.post("/api/users", async (request, reply) => {
  try {
    const {
      username,
      password,
      storeName,
      template,
      premium,
      modules = [],
      telefone,
      endereco,
      facebookLink,
      instagramLink,
      horarioAbertura,
      horarioFechamento,
      diasFuncionamento = [],
      logoUrl,
      cidade,
      estado,
    } = request.body;

    const exists = await prisma.user.findUnique({ where: { username } });
    if (exists) return reply.status(400).send({ message: "Usuário já existe" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const storeSlug = storeName.toLowerCase().replace(/\s+/g, "-");

    const newUser = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        role: Role.client,
        store: {
          create: {
            name: storeName,
            slug: storeSlug,
            isActive: true,
            isPremium: premium === true || premium === "true",
            template: template || "fastfood",
            modules: { set: modules },
            telefone,
            endereco,
            facebookLink,
            instagramLink,
            horarioAbertura,
            horarioFechamento,
            diasFuncionamento: { set: diasFuncionamento },
            logoUrl,
            cidade,
            estado,
          },
        },
      },
      include: { store: true },
    });

    reply.status(201).send({
      id: newUser.id,
      username: newUser.username,
      storeSlug: newUser.store.slug,
      modules: newUser.store.modules,
    });
  } catch (err) {
    app.log.error(err);
    reply.status(500).send({ message: "Erro ao criar usuário" });
  }
});

// Rota para criar administrador
// (para administradores)
// Esta rota é usada para criar novos administradores (admin)
// Apenas o administrador principal (isRoot) pode criar novos admins
app.post("/api/admins", async (request, reply) => {
  try {
    const { username, password, isRoot } = request.body;

    const exists = await prisma.user.findUnique({ where: { username } });
    if (exists) return reply.status(400).send({ message: "Usuário já existe" });

    if (isRoot) {
      const existingRoot = await prisma.user.findFirst({
        where: { isRoot: true },
      });
      if (existingRoot) {
        return reply
          .status(403)
          .send({ message: "Já existe um administrador principal (isRoot)" });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newAdmin = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        role: Role.admin,
        isRoot: isRoot === true || isRoot === "true",
      },
    });

    reply.status(201).send({
      id: newAdmin.id,
      username: newAdmin.username,
      role: newAdmin.role,
      isRoot: newAdmin.isRoot,
    });
  } catch (err) {
    app.log.error(err);
    reply.status(500).send({ message: "Erro ao criar admin" });
  }
});

// Rota para listar produtos
// (para lojas)
// Esta rota é usada para exibir todos os produtos de uma loja autenticada
app.get(
  "/api/products",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const store = await prisma.store.findFirst({
        where: { userId: request.user.id },
      });
      if (!store)
        return reply.status(404).send({ message: "Loja não encontrada" });

      const products = await prisma.product.findMany({
        where: { storeId: store.id },
      });
      reply.send(products);
    } catch (error) {
      reply.status(500).send({ message: "Erro ao buscar produtos" });
    }
  }
);

// Rota para criar produto
// (para lojas)
app.post(
  "/api/products",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const {
        title,
        description,
        imageUrl,
        price,
        promoPrice,
        category,
        isSoldOut,
      } = request.body;

      const store = await prisma.store.findFirst({
        where: { userId: request.user.id },
      });

      if (!store)
        return reply.status(404).send({ message: "Loja não encontrada" });

      const newProduct = await prisma.product.create({
        data: {
          title,
          description,
          imageUrl,
          price: parseFloat(price),
          promoPrice: promoPrice ? parseFloat(promoPrice) : null,
          category: category || "other",
          isSoldOut: isSoldOut === true || isSoldOut === "true", // <- novo campo
          storeId: store.id,
        },
      });

      reply.status(201).send(newProduct);
    } catch (error) {
      reply.status(500).send({ message: "Erro ao criar produto" });
    }
  }
);

// Rota para listar lojas públicas
// (para lojas)
// Esta rota é usada para exibir todas as lojas disponíveis publicamente
app.get("/api/stores/public", async (request, reply) => {
  try {
    const stores = await prisma.store.findMany({
      select: {
        id: true,
        name: true,
        slug: true,
        isActive: true,
        isPremium: true,
        userId: true,
        template: true,
        endereco: true,
        telefone: true,
        user: {
          select: {
            username: true,
          },
        },
      },
    });
    reply.send(stores);
  } catch (error) {
    app.log.error("Erro ao buscar lojas:", error);
    reply.status(500).send({ message: "Erro ao buscar lojas" });
  }
});

//essa rota é usada para buscar detalhes de um usuário específico
// (para lojas)
// Ela retorna informações do usuário e sua loja associada
// é usada para exibir os dados no modal para atualizar informações da loja caso precise
app.get("/api/users/:id", async (request, reply) => {
  try {
    const { id } = request.params;
    const user = await prisma.user.findUnique({
      where: { id },
      include: { store: true },
    });

    if (!user)
      return reply.status(404).send({ message: "Usuário não encontrado" });

    reply.send(user);
  } catch (err) {
    app.log.error(err);
    reply.status(500).send({ message: "Erro ao buscar usuário" });
  }
});

//essa rota serve para atualizar as informações de um usuário e sua loja associada
// para admin no dashboard clicando no botao "Editar Loja"
app.put("/api/users/:id", async (request, reply) => {
  try {
    const { id } = request.params;
    const {
      username,
      password,
      storeName,
      template,
      premium,
      modules = [],
      telefone,
      endereco,
      facebookLink,
      instagramLink,
      horarioAbertura,
      horarioFechamento,
      diasFuncionamento = [],
      logoUrl,
      cidade,
      estado,
    } = request.body;

    const hashedPassword = password
      ? await bcrypt.hash(password, 10)
      : undefined;

    const updatedUser = await prisma.user.update({
      where: { id },
      data: {
        username,
        ...(hashedPassword && { password: hashedPassword }),
        store: {
          update: {
            name: storeName,
            template,
            isPremium: premium === true || premium === "true",
            modules: { set: modules },
            telefone,
            endereco,
            facebookLink,
            instagramLink,
            horarioAbertura,
            horarioFechamento,
            diasFuncionamento: { set: diasFuncionamento },
            logoUrl,
            cidade,
            estado,
          },
        },
      },
      include: { store: true },
    });

    reply.send({ message: "Loja atualizada com sucesso", updatedUser });
  } catch (err) {
    app.log.error(err);
    reply.status(500).send({ message: "Erro ao atualizar loja" });
  }
});

// Rota para buscar usuário pelo storeId
//usado pra recuperar informações do usuário associado a uma loja específica
app.get("/api/users/by-store/:storeId", async (request, reply) => {
  const { storeId } = request.params;

  const user = await prisma.user.findFirst({
    where: { store: { id: storeId } },
    include: { store: true },
  });

  if (!user) {
    return reply.status(404).send({ message: "Usuário não encontrado" });
  }

  reply.send(user);
});

// Rota para buscar loja pública pelo slug
// (para lojas)
// Esta rota é usada para exibir os detalhes de uma loja específica
app.get("/api/stores/:slug", async (request, reply) => {
  try {
    const { slug } = request.params;
    const store = await prisma.store.findUnique({
      where: { slug },
      include: { products: true },
    });

    if (!store)
      return reply.status(404).send({ message: "Loja não encontrada" });

    reply.send(store);
  } catch (error) {
    reply.status(500).send({ message: "Erro ao buscar loja" });
  }
});

// Rota para listar produtos de uma loja pública
// (para lojas)
// Esta rota é usada para exibir os produtos de uma loja específica
app.get("/api/stores/:storeId/products", async (request, reply) => {
  try {
    const { storeId } = request.params;
    const products = await prisma.product.findMany({ where: { storeId } });
    reply.send(products);
  } catch (error) {
    reply.status(500).send({ message: "Erro ao buscar produtos da loja" });
  }
});

// Rota para criar produto
// (para lojas)
// Esta rota é usada para adicionar produtos a uma loja específica
app.post(
  "/api/stores/:storeId/products",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const { storeId } = request.params;
      const { title, description, imageUrl, price } = request.body;

      const store = await prisma.store.findUnique({ where: { id: storeId } });
      if (!store)
        return reply.status(404).send({ message: "Loja não encontrada" });

      if (store.userId !== request.user.id && request.user.role !== "admin") {
        return reply.status(403).send({
          message: "Sem permissão para adicionar produto nesta loja",
        });
      }

      const newProduct = await prisma.product.create({
        data: {
          title,
          description,
          imageUrl,
          price: parseFloat(price),
          storeId: store.id,
        },
      });

      reply.status(201).send(newProduct);
    } catch (error) {
      reply.status(500).send({ message: "Erro ao criar produto" });
    }
  }
);

// Rota para atualizar produto
// (para lojas)
app.patch(
  "/api/products/:id",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const { id } = request.params;
      const updates = request.body;

      const product = await prisma.product.findUnique({ where: { id } });
      if (!product)
        return reply.status(404).send({ message: "Produto não encontrado" });

      const store = await prisma.store.findUnique({
        where: { id: product.storeId },
      });
      if (
        !store ||
        (store.userId !== request.user.id && request.user.role !== "admin")
      ) {
        return reply
          .status(403)
          .send({ message: "Sem permissão para editar este produto" });
      }

      if (updates.imageUrl && updates.imageUrl !== product.imageUrl) {
        const oldImageName = path.basename(product.imageUrl);
        const oldImagePath = path.join(process.cwd(), "uploads", oldImageName);

        fs.unlink(oldImagePath, (err) => {
          if (err) {
            app.log.warn(
              `Erro ao remover imagem antiga (${oldImageName}): ${err.message}`
            );
          } else {
            app.log.info(`Imagem antiga removida: ${oldImageName}`);
          }
        });
      }

      const updatedProduct = await prisma.product.update({
        where: { id },
        data: {
          ...updates,
          price:
            updates.price !== undefined ? parseFloat(updates.price) : undefined,
          promoPrice:
            updates.promoPrice !== undefined
              ? parseFloat(updates.promoPrice)
              : undefined,
        },
      });

      reply.send(updatedProduct);
    } catch (error) {
      app.log.error("Erro ao atualizar produto:", error);
      reply.status(500).send({ message: "Erro ao atualizar produto" });
    }
  }
);

// Rota para deletar produto
// (para lojas)
app.delete(
  "/api/products/:id",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const { id } = request.params;

      const product = await prisma.product.findUnique({ where: { id } });
      if (!product)
        return reply.status(404).send({ message: "Produto não encontrado" });

      const store = await prisma.store.findUnique({
        where: { id: product.storeId },
      });
      if (store.userId !== request.user.id && request.user.role !== "admin") {
        return reply
          .status(403)
          .send({ message: "Sem permissão para deletar este produto" });
      }

      if (product.imageUrl) {
        const imagePath = path.join("uploads", path.basename(product.imageUrl));
        fs.unlink(imagePath, (err) => {
          if (err) app.log.warn("Erro ao excluir imagem:", err.message);
          else app.log.info("Imagem excluída:", imagePath);
        });
      }

      await prisma.product.delete({ where: { id } });
      reply.status(204).send();
    } catch (error) {
      app.log.error("Erro ao deletar produto:", error);
      reply.status(500).send({ message: "Erro ao deletar produto" });
    }
  }
);

// Rota para criar pedido
// (para clientes LOJAS)
app.post("/api/orders", async (request, reply) => {
  console.log("storeSlug recebido:", request.body.storeSlug);

  try {
    const { items, total, customer, storeSlug } = request.body;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return reply.status(400).send({ message: "Carrinho vazio ou inválido" });
    }
    if (!customer || !customer.name || !customer.phone || !customer.address) {
      return reply
        .status(400)
        .send({ message: "Dados do cliente incompletos" });
    }

    const store = await prisma.store.findUnique({ where: { slug: storeSlug } });
    if (!store) {
      return reply.status(404).send({ message: "Loja não encontrada" });
    }

    const order = await prisma.order.create({
      data: {
        storeId: store.id,
        total,
        status: "pending",
        customerName: customer.name,
        customerPhone: customer.phone,
        customerAddress: customer.address,
        paymentMethod: customer.paymentMethod,
        items: {
          create: items.map((item) => ({
            productId: item.id,
            quantity: item.quantity,
            price: item.price,
          })),
        },
      },
      include: { items: true },
    });

    broadcast({ tipo: 'novo-pedido', pedido: order });

    reply.status(201).send(order);
  } catch (error) {
    app.log.error(error);
    reply.status(500).send({ message: "Erro ao criar pedido" });
  }
});

// Rota para listar pedidos de uma loja autenticada
// (para lojas)
app.get(
  "/api/list-orders",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const store = await prisma.store.findFirst({
        where: { userId: request.user.id },
      });

      if (!store) {
        return reply.status(404).send({ message: "Loja não encontrada" });
      }

      const { status } = request.query;

      const orders = await prisma.order.findMany({
        where: {
          storeId: store.id,
          ...(status ? { status } : {}),
        },
        orderBy: { createdAt: "desc" },
        include: {
          items: {
            include: {
              product: true,
            },
          },
        },
      });

      reply.send(orders);
    } catch (error) {
      app.log.error(error);
      reply.status(500).send({ message: "Erro ao buscar pedidos" });
    }
  }
);


// Atualiza o status de um pedido
app.put("/api/orders/:orderId/status", async (request, reply) => {
  const { orderId } = request.params;
  const { status } = request.body;

  try {
    // Validação básica
    const allowedStatuses = [
      "received",
      "preparing",
      "ready",
      "out_for_delivery",
      "delivered",
    ];

    if (!allowedStatuses.includes(status)) {
      return reply.status(400).send({ message: "Status inválido" });
    }

    // Verifica se o pedido existe
    const existingOrder = await prisma.order.findUnique({
      where: { id: orderId },
    });

    if (!existingOrder) {
      return reply.status(404).send({ message: "Pedido não encontrado" });
    }

    // Atualiza o status
    const updated = await prisma.order.update({
      where: { id: orderId },
      data: { status },
    });

    reply.send(updated);
  } catch (error) {
    app.log.error(error);
    reply.status(500).send({ message: "Erro ao atualizar status do pedido" });
  }
});

// Rota para atualizar status Premium da loja admin altera isso
app.patch(
  "/api/stores/:id/premium",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const { id } = request.params;
    const { isPremium } = request.body;

    try {
      const store = await prisma.store.update({
        where: { id },
        data: { isPremium: isPremium === true || isPremium === "true" },
      });

      reply.send({ success: true, isPremium: store.isPremium });
    } catch (err) {
      app.log.error(err);
      reply.status(500).send({ message: "Erro ao atualizar status Premium" });
    }
  }
);

// Rota para atualizar status da loja (ativa/inativa) admin altera isso
app.patch(
  "/api/stores/:id/status",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const { id } = request.params;
    const { isActive } = request.body;

    try {
      const store = await prisma.store.update({
        where: { id },
        data: { isActive: isActive === true || isActive === "true" },
      });

      reply.send({ success: true, isActive: store.isActive });
    } catch (err) {
      app.log.error("Erro ao atualizar status da loja:", err);
      reply.status(500).send({ message: "Erro ao atualizar status da loja" });
    }
  }
);

// Rota para deletar Lojas (admin)
// (para administradores)
app.delete(
  "/api/stores/:id",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const { id } = request.params;

    if (request.user.role !== Role.admin) {
      return reply
        .status(403)
        .send({ message: "Apenas administradores podem deletar lojas" });
    }

    try {
      const store = await prisma.store.findUnique({ where: { id } });
      if (!store)
        return reply.status(404).send({ message: "Loja não encontrada" });

      await prisma.store.delete({ where: { id } });
      await prisma.user.delete({ where: { id: store.userId } });

      reply.send({ success: true });
    } catch (err) {
      app.log.error("Erro ao deletar loja e usuário:", err);
      reply.status(500).send({ message: "Erro ao deletar loja e usuário" });
    }
  }
);

// Rota para deletar usuário
// (para administradores)
app.delete(
  "/api/users/:id",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const { id } = request.params;

    if (request.user.role !== Role.admin) {
      return reply
        .status(403)
        .send({ message: "Apenas administradores podem deletar usuários" });
    }

    try {
      const user = await prisma.user.findUnique({
        where: { id },
        include: { store: true },
      });
      if (!user)
        return reply.status(404).send({ message: "Usuário não encontrado" });

      if (user.isRoot) {
        return reply.status(403).send({
          message: "Não é permitido deletar o administrador principal (isRoot)",
        });
      }

      if (user.store) {
        const storeId = user.store.id;

        await prisma.orderItem.deleteMany({ where: { order: { storeId } } });
        await prisma.order.deleteMany({ where: { storeId } });
        await prisma.product.deleteMany({ where: { storeId } });

        await prisma.store.delete({ where: { id: storeId } });
      }

      await prisma.user.delete({ where: { id: user.id } });

      reply.send({ success: true, message: "Usuário deletado com sucesso" });
    } catch (err) {
      app.log.error("Erro ao deletar usuário:", err);
      reply
        .status(500)
        .send({ message: "Erro ao deletar usuário", error: err.message });
    }
  }
);

// rota pública para criar agendamento
app.post("/api/agendamentos", async (request, reply) => {
  try {
    const {
      clienteNome,
      dataHora,
      profissional,
      observacoes,
      customData,
      storeId, // agora vem direto do frontend
    } = request.body;

    if (!clienteNome || !dataHora || !storeId) {
      return reply
        .status(400)
        .send({ message: "Nome, data/hora e ID da loja são obrigatórios." });
    }

    // Confere se a loja existe
    const store = await prisma.store.findUnique({
      where: { id: storeId },
    });

    if (!store) {
      return reply.status(404).send({ message: "Loja não encontrada." });
    }

    const agendamento = await prisma.agendamento.create({
      data: {
        storeId: store.id,
        clienteNome,
        dataHora: new Date(dataHora),
        profissional,
        observacoes,
        customData, // campos extras opcionais
        status: "pendente",
      },
    });

    return reply.status(201).send(agendamento);
  } catch (error) {
    console.error("Erro ao criar agendamento:", error);
    return reply
      .status(500)
      .send({ message: "Erro interno ao criar agendamento." });
  }
});

//Lista agendamentos de uma loja autenticada
app.get(
  "/api/agendamentos",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const store = await prisma.store.findFirst({
        where: { userId: request.user.id },
      });

      if (!store) {
        return reply.status(404).send({ message: "Loja não encontrada." });
      }

      const agendamentos = await prisma.agendamento.findMany({
        where: { storeId: store.id },
        orderBy: { dataHora: "asc" },
      });

      return reply.send(agendamentos);
    } catch (error) {
      console.error("Erro ao buscar agendamentos:", error);
      return reply
        .status(500)
        .send({ message: "Erro interno ao buscar agendamentos." });
    }
  }
);

//confirma ou cancela agendamento de uma loja autenticada
app.patch(
  "/api/agendamentos/:id/status",
  { preHandler: app.authenticate },
  async (request, reply) => {
    try {
      const { id } = request.params;
      const { status } = request.body;

      const store = await prisma.store.findFirst({
        where: { userId: request.user.id },
      });

      if (!store) {
        return reply.status(404).send({ message: "Loja não encontrada." });
      }

      const agendamento = await prisma.agendamento.findUnique({
        where: { id },
      });

      if (!agendamento || agendamento.storeId !== store.id) {
        return reply
          .status(404)
          .send({ message: "Agendamento não encontrado." });
      }

      const updated = await prisma.agendamento.update({
        where: { id },
        data: { status },
      });

      return reply.send(updated);
    } catch (error) {
      console.error("Erro ao atualizar status do agendamento:", error);
      return reply
        .status(500)
        .send({ message: "Erro ao atualizar agendamento." });
    }
  }
);

//deletar agendamento de uma loja autenticada
app.delete(
  "/api/agendamentos/:id",
  { preHandler: app.authenticate },
  async (request, reply) => {
    const { id } = request.params;

    try {
      const store = await prisma.store.findFirst({
        where: { userId: request.user.id },
      });

      if (!store) {
        return reply.status(404).send({ message: "Loja não encontrada" });
      }

      const agendamento = await prisma.agendamento.findUnique({
        where: { id },
      });

      if (!agendamento || agendamento.storeId !== store.id) {
        return reply
          .status(404)
          .send({ message: "Agendamento não encontrado" });
      }

      await prisma.agendamento.delete({
        where: { id },
      });

      return reply
        .status(200)
        .send({ message: "Agendamento deletado com sucesso" });
    } catch (error) {
      console.error(error);
      return reply.status(500).send({ message: "Erro ao deletar agendamento" });
    }
  }
);

// Iniciar servidor
const start = async () => {
  try {
    // Criar usuário admin padrão
    await createDefaultAdmin();
    
    await app.listen({ port: Number(PORT), host: "0.0.0.0" });
    app.log.info(`Servidor rodando na porta ${PORT}`);

    // Inicia WebSocket em cima do mesmo servidor Fastify
    const wss = new WebSocketServer({ server: app.server });

    wss.on('connection', (ws) => {
      wsClients.add(ws);

      ws.on('close', () => {
        wsClients.delete(ws);
      });
    });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
