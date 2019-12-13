package io.smallrye.mutiny.vertx.codegen.lang;


import java.io.PrintWriter;

import io.vertx.codegen.ClassModel;
import io.vertx.codegen.ConstantInfo;
import io.vertx.codegen.doc.Doc;
import io.vertx.codegen.doc.Token;

import static io.smallrye.mutiny.vertx.codegen.lang.CodeGenHelper.genConvReturn;

public class ConstantCodeWriter implements CodeWriter {

    @Override
    public void generate(ClassModel model, PrintWriter writer) {
        for (ConstantInfo constant : model.getConstants()) {
            genConstant(model, constant, writer);
        }
    }

    private void genConstant(ClassModel model, ConstantInfo constant, PrintWriter writer) {
        Doc doc = constant.getDoc();
        if (doc != null) {
            writer.println("  /**");
            Token.toHtml(doc.getTokens(), "   *", CodeGenHelper::renderLinkToHtml, "\n", writer);
            writer.println("   */");
        }
        writer.print(model.isConcrete() ? "  public static final" : "");
        writer.format(" %s %s = %s;%n",
                genTypeName(constant.getType()),
                constant.getName(),
                genConvReturn(constant.getType(), null, model.getType().getName() + "." + constant.getName()));
    }

}
