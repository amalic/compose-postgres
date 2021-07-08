package io.eol.service.createdb;

import org.hibernate.procedure.ProcedureOutputs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.persistence.EntityManager;
import javax.persistence.ParameterMode;
import javax.persistence.PersistenceContext;
import javax.persistence.StoredProcedureQuery;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@SpringBootTest
class PostgresqlFunctionTest {

    @PersistenceContext
    EntityManager entityManager;

    @BeforeEach
    void setup() {

    }

    @Test
    public void whenCreateRoleFunctionThenANewServiceRoleIsCreated() {

        StoredProcedureQuery query = entityManager
                .createStoredProcedureQuery("create_role")
                .registerStoredProcedureParameter(
                        "v_svcname",
                        String.class,
                        ParameterMode.IN
                )
                .registerStoredProcedureParameter(
                        "v_role",
                        String.class,
                        ParameterMode.IN
                )
                .registerStoredProcedureParameter(
                        "v_pghashed_password",
                        String.class,
                        ParameterMode.IN
                )
                .registerStoredProcedureParameter(
                        "resultMessage",
                        String.class,
                        ParameterMode.OUT
                )
                .setParameter("v_svcname", "chuck")
                .setParameter("v_role", "admin")
                .setParameter("v_pghashed_password", "md5chuck");

        try {
            query.execute();

            String resultMessage = (String) query
                    .getOutputParameterValue("resultMessage");

            assertEquals("OK: 'GRANT db_admin TO chuck_admin'", resultMessage);
        } finally {
            query.unwrap(ProcedureOutputs.class)
                    .release();
        }
    }
}
