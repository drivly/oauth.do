import { NextRequest, NextResponse } from "next/server";
import { auth } from "../../../auth";

export async function POST(request: NextRequest) {
  const body = await request.json();
  
  try {
    console.log("Registering client:", body);
    
    const client = {
      clientId: "apis_do_client_id",
      clientSecret: "apis_do_client_secret",
      name: body.name,
      redirect_uris: body.redirect_uris,
    };
    
    return NextResponse.json(client);
  } catch (error) {
    console.error("Error registering client:", error);
    return NextResponse.json({ error: "Failed to register client" }, { status: 500 });
  }
}
