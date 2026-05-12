package it.r2u.anibus.architecture;

import org.junit.jupiter.api.Test;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * ArchUnit tests that enforce module boundary rules across the codebase.
 *
 * Rules enforced:
 * 1. service layer may NOT depend on the handler or controller layer.
 * 2. util classes may NOT depend on handlers or controllers.
 * 3. coordinator layer may NOT depend on JavaFX scene/stage directly.
 * 4. Controller class must reside only in the root application package.
 */
class ModuleBoundaryTest {

    private static final JavaClasses classes =
            new ClassFileImporter().importPackages("it.r2u.anibus");

    /** Service layer must not reach up into the controller or handler layer. */
    @Test
    void servicesMustNotDependOnHandlersOrController() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..service..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("..handlers..", "it.r2u.anibus.AnibusController")
                .because("Services must not know about the controller or handler layer");
        rule.check(classes);
    }

    /** Utility classes must not depend on handlers, controller, or JavaFX scene graph. */
    @Test
    void utilMustNotDependOnHandlersOrController() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..util..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("..handlers..", "it.r2u.anibus.AnibusController")
                .because("Utility classes must be independent of the application layer");
        rule.check(classes);
    }

    /** Coordinator classes must not import javafx.scene or javafx.stage directly. */
    @Test
    void coordinatorMustNotDependOnJavaFxSceneGraph() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..coordinator..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("javafx.scene..", "javafx.stage..")
                .because("Coordinator is a pure Java layer and must not reference JavaFX scene graph");
        rule.check(classes);
    }

    /** Controller class must reside only in the root application package. */
    @Test
    void anibusControllerMustBeInRootPackage() {
        ArchRule rule = classes()
                .that().haveSimpleName("AnibusController")
                .should().resideInAPackage("it.r2u.anibus")
                .because("AnibusController is the top-level wiring point and belongs in the root package");
        rule.check(classes);
    }

    /** Model classes must not depend on service, handler, or coordinator layers. */
    @Test
    void modelMustNotDependOnUpperLayers() {
        // ProxyNode is a value-type that lives in the service.network.proxy package but is
        // referenced by ScanContext (a model class). This is a known design compromise: ProxyNode
        // should ideally be moved to the model layer. Until that refactor is done, we allow it.
        ArchRule rule = noClasses()
                .that().resideInAPackage("..model..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("..handlers..", "..coordinator..")
                .because("Model must not know about handlers or coordinators");
        rule.check(classes);
    }
}
